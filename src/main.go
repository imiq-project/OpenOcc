package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
	"golang.org/x/crypto/acme/autocert"
)

type Vehicle struct {
	Id        ClientIdType  `gorm:"column:id;primaryKey"           json:"Id"`
	Name      string        `gorm:"column:name;not null"           json:"Name"`
	Lat       float64       `gorm:"column:lat;not null;default:0"  json:"Lat"`
	Lon       float64       `gorm:"column:lon;not null;default:0"  json:"Lon"`
	Connected bool          `gorm:"-"                              json:"Connected"`
	Key       EncryptionKey `gorm:"column:key;not null;default:''" json:"-"`
}

func (Vehicle) TableName() string { return "vehicles" }

type StatusMsg struct {
	Type     string
	Vehicles []Vehicle
}

func AltSvc(h3Port string) func(http.Handler) http.Handler {
	altValue := `h3=":` + h3Port + `"; ma=86400`

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Alt-Svc", altValue)
			next.ServeHTTP(w, r)
		})
	}
}

func GetEnvOrPanic(key string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		panic(key + " is not set")
	}
	return value
}

func GetEnvOrDefault(key, fallback string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		return fallback
	}
	return value
}

func main() {
	express_turn_user := GetEnvOrPanic("EXPRESS_TURN_USERNAME")
	express_turn_pass := GetEnvOrPanic("EXPRESS_TURN_PASSWORD")

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Database
	dbConnStr := GetEnvOrDefault("DATABASE_URL", "postgres://occ:occ@localhost:5432/occ?sslmode=disable")
	sqlDB, err := OpenSQLPool(dbConnStr)
	if err != nil {
		log.Fatalf("open db pool: %v", err)
	}
	defer sqlDB.Close()

	if err := RunMigrations(sqlDB); err != nil {
		log.Fatalf("migrations: %v", err)
	}

	db := InitGORM(sqlDB)

	vehicles, err := LoadVehicles(db)
	if err != nil {
		log.Fatalf("failed to load vehicles: %v", err)
	}
	log.Printf("Loaded %d vehicles from database", len(vehicles))

	var hostname string
	flag.StringVar(&hostname, "hostname", "localhost", "the server's host name")
	var useAcme bool
	flag.BoolVar(&useAcme, "use-acme", false, "use ACME (Let's Encrypt) instead of self-signed certificates")
	flag.Parse()

	var tlsConf *tls.Config
	const certdDir = "/certs"
	if useAcme {
		m := &autocert.Manager{
			Cache:      autocert.DirCache(certdDir),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(hostname),
		}

		// HTTP server: redirect all traffic to HTTPS
		go func() {
			httpServer := &http.Server{
				Addr:    ":80",
				Handler: m.HTTPHandler(nil), // HTTP-01 challenge + redirect
			}
			log.Fatal(httpServer.ListenAndServe())
		}()

		tlsConf = m.TLSConfig()
	} else {
		cert, err := createOrLoadCertificates(hostname, certdDir)
		if err != nil {
			log.Fatalf("failed to load TLS cert: %v", err)
		}

		// redirect HTTP to HTTPS
		go func() {
			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				target := "https://" + r.Host + r.URL.RequestURI()
				http.Redirect(w, r, target, http.StatusMovedPermanently)
			})
			srv := &http.Server{
				Addr:    ":80",
				Handler: AltSvc("443")(mux),
			}
			log.Fatal(srv.ListenAndServe())
		}()

		tlsConf = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}
	}

	mux := http.NewServeMux()

	h2srv := &http.Server{
		Addr:      ":443",
		Handler:   AltSvc("443")(mux),
		TLSConfig: http3.ConfigureTLSConfig(tlsConf),
	}

	h3srv := http3.Server{
		Addr:      ":443",
		Handler:   AltSvc("443")(mux),
		TLSConfig: tlsConf,
		QUICConfig: &quic.Config{
			MaxIdleTimeout:  10 * time.Second,
			EnableDatagrams: true,
		},
	}

	wtSrv := webtransport.Server{
		H3: h3srv,
	}

	// Proxy to next.js
	target, _ := url.Parse("http://client:3000")
	proxy := httputil.NewSingleHostReverseProxy(target)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Proxying request for", r.URL.Path, "to", target)
		proxy.ServeHTTP(w, r)
	})

	// ICE Servers
	mux.HandleFunc("/iceServers", func(w http.ResponseWriter, r *http.Request) {
		type ICECredential struct {
			URLs       []string `json:"urls"`
			Username   string   `json:"username"`
			Credential string   `json:"credential"`
		}
		type Response struct {
			IceServers []ICECredential `json:"iceServers"`
		}

		response := Response{
			IceServers: []ICECredential{
				{
					URLs: []string{
						"stun:stun.l.google.com:19302",
					},
					Username:   "",
					Credential: "",
				},
				{
					URLs: []string{
						"turn:free.expressturn.com:3478?transport=udp",
						"turn:free.expressturn.com:3478?transport=tcp",
						"turns:free.expressturn.com:5349",
					},
					Username:   express_turn_user,
					Credential: express_turn_pass, // TODO: generate time-limited credential
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	})

	vehicleBroker := NewWebTransportBroker()
	occBroker := NewWebTransportBroker()

	// Vehicle store — shared state between broker loop and API handlers
	store := &VehicleStore{
		vehicles:      vehicles,
		db:            db,
		occBroker:     &occBroker,
		vehicleBroker: &vehicleBroker,
	}

	// Initial status broadcast
	store.broadcastStatus()

	// REST API
	RegisterAPIRoutes(mux, store)

	// Serve webtransport for vehicles
	mux.HandleFunc("/wt-vehicle", func(w http.ResponseWriter, r *http.Request) {
		// TODO: auth
		id := r.URL.Query().Get("VehicleId")
		log.Println("Connection attempt by vehicle", id)
		session, err := wtSrv.Upgrade(w, r)
		if err != nil {
			log.Printf("upgrading failed: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		vehicleBroker.HandleSession(ClientIdType(id), session)
	})

	// Serve webtransport for control centers
	mux.HandleFunc("/wt-occ", func(w http.ResponseWriter, r *http.Request) {
		// TODO: auth
		id := r.URL.Query().Get("OccId")
		session, err := wtSrv.Upgrade(w, r)
		if err != nil {
			log.Printf("upgrading failed: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		go occBroker.HandleSession(ClientIdType(id), session)
	})

	mux.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {
		recipient := r.URL.Query().Get("Recipient")
		bytes, _ := io.ReadAll(r.Body)
		err := vehicleBroker.sendMessage(ClientIdType(recipient), bytes)
		if err == nil {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotAcceptable)
			log.Println(err)
		}
	})

	// Connect the two brokers
	type IncomingMsg struct {
		Recipient ClientIdType
	}
	go func() {
		for {
			select {
			case id := <-vehicleBroker.Connected:
				store.mu.Lock()
				if v, ok := store.vehicles[id]; ok {
					v.Connected = true
				}
				store.mu.Unlock()
				store.broadcastStatus()

			case id := <-vehicleBroker.Disconnected:
				store.mu.Lock()
				if v, ok := store.vehicles[id]; ok {
					v.Connected = false
				}
				store.mu.Unlock()
				store.broadcastStatus()

			case msg := <-vehicleBroker.Messages:
				result := IncomingMsg{}
				err := json.Unmarshal(msg.Payload, &result)
				if err != nil {
					log.Println("Received invalid message")
				}
				occBroker.sendMessage(result.Recipient, msg.Payload)

			case msg := <-occBroker.Messages:
				result := IncomingMsg{}
				err := json.Unmarshal(msg.Payload, &result)
				if err != nil {
					log.Println("Received invalid message from OCC")
					continue
				}
				vehicleBroker.sendMessage(result.Recipient, msg.Payload)

			case <-vehicleBroker.Datagrams:
			case <-occBroker.Connected:
			case <-occBroker.Disconnected:
			case <-occBroker.Datagrams:
			}
		}
	}()

	go func() {
		log.Println("Starting HTTPS server (TCP/TLS) on", h2srv.Addr)
		err := h2srv.ListenAndServeTLS("", "")
		log.Fatal(err)
	}()

	log.Println("Starting HTTP/3 server (UDP/QUIC) on", h3srv.Addr)
	err = wtSrv.ListenAndServe()
	log.Fatal("HTTP/3 failed:", err)
}
