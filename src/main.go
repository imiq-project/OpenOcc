package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
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
	Id        ClientIdType
	Name      string
	Lat       float64
	Lon       float64
	Connected bool
	key       string
	IoConf    map[string]any
}

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

func icdServers(expressTurnUser string, expressTurnPass string) []byte {
	type ICECredential struct {
		URLs       []string `json:"urls"`
		Username   string   `json:"username"`
		Credential string   `json:"credential"`
	}
	type ServersMessage struct {
		Type       string
		IceServers []ICECredential `json:"iceServers"`
	}

	msg := ServersMessage{
		Type: "iceServers",
		IceServers: []ICECredential{
			ICECredential{
				URLs: []string{
					"stun:stun.l.google.com:19302",
				},
				Username:   "",
				Credential: "",
			},
			ICECredential{
				URLs: []string{
					"turn:free.expressturn.com:3478?transport=udp",
					"turn:free.expressturn.com:3478?transport=tcp",
					"turns:free.expressturn.com:5349",
				},
				Username:   expressTurnUser,
				Credential: expressTurnPass, // TODO: generate time-limited credential
			},
		},
	}
	iceMessage, _ := json.Marshal(msg)
	return iceMessage
}

func GetEnvOrDefault(key, fallback string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		return fallback
	}
	return value
}

func main() {
	expressTurnUser := GetEnvOrPanic("EXPRESS_TURN_USERNAME")
	expressTurnPass := GetEnvOrPanic("EXPRESS_TURN_PASSWORD")

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Database
	dbConnStr := GetEnvOrDefault("DATABASE_URL", "postgres://occ:occ@localhost:5432/occ?sslmode=disable")
	db := InitDB(dbConnStr)
	defer db.Close()

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
		// log.Println("Proxying request for", r.URL.Path, "to", target)
		proxy.ServeHTTP(w, r)
	})

	vehicleBroker := NewWebTransportBroker()
	operatorBroker := NewWebTransportBroker()

	// Vehicle store — shared state between broker loop and API handlers
	store := &VehicleStore{
		vehicles:       vehicles,
		db:             db,
		operatorBroker: &operatorBroker,
		vehicleBroker:  &vehicleBroker,
	}

	// Initial status broadcast
	store.broadcastStatus()

	// REST API
	RegisterAPIRoutes(mux, store)

	// Serve webtransport for vehicles
	mux.HandleFunc("/wt-vehicle", func(w http.ResponseWriter, r *http.Request) {
		// TODO: auth
		id := r.URL.Query().Get("VehicleId")
		vehicle, ok := store.vehicles[ClientIdType(id)]
		if !ok {
			http.Error(w, "unknown vehicle", http.StatusBadRequest)
			return
		}
		err := json.Unmarshal([]byte(r.URL.Query().Get("IoConf")), &vehicle.IoConf)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		log.Println("Connection attempt by vehicle", id)
		session, err := wtSrv.Upgrade(w, r)
		if err != nil {
			log.Printf("upgrading failed: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		vehicleBroker.HandleSession(ClientIdType(id), session)
	})

	type StatusMsg struct {
		Type     string
		Vehicles []Vehicle
	}

	// Serve webtransport for control centers
	mux.HandleFunc("/wt-operator", func(w http.ResponseWriter, r *http.Request) {
		// TODO: auth
		id := r.URL.Query().Get("OccId")
		session, err := wtSrv.Upgrade(w, r)
		if err != nil {
			log.Printf("upgrading failed: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		go operatorBroker.HandleSession(ClientIdType(id), session)
	})

	// Connect the two brokers
	type IncomingMsg struct {
		To ClientIdType
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
				vehicleBroker.sendMessage(id, icdServers(expressTurnUser, expressTurnPass))
				statusMessage, _ := json.Marshal(StatusMsg{"status", store.snapshot()})
				operatorBroker.broadcast("", statusMessage)
			case id := <-vehicleBroker.Disconnected:
				store.mu.Lock()
				if v, ok := store.vehicles[id]; ok {
					v.Connected = false
				}
				store.mu.Unlock()
				statusMessage, _ := json.Marshal(StatusMsg{"status", store.snapshot()})
				operatorBroker.broadcast("", statusMessage)
			case msg := <-vehicleBroker.Messages:
				result := IncomingMsg{}
				err := json.Unmarshal(msg.Payload, &result)
				if err != nil {
					log.Println("Received invalid message")
				}
				operatorBroker.sendMessage(result.To, msg.Payload)
			case <-vehicleBroker.Datagrams:
			case id := <-operatorBroker.Connected:
				statusMessage, _ := json.Marshal(StatusMsg{"status", store.snapshot()})
				operatorBroker.sendMessage(id, statusMessage)
				operatorBroker.sendMessage(id, icdServers(expressTurnUser, expressTurnPass))
			case <-operatorBroker.Disconnected:
			case msg := <-operatorBroker.Messages:
				result := IncomingMsg{}
				err := json.Unmarshal(msg.Payload, &result)
				if err != nil {
					log.Println("Received invalid message from OCC")
					continue
				}
				vehicleBroker.sendMessage(result.To, msg.Payload)
			case <-operatorBroker.Datagrams:
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
