package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
	"golang.org/x/crypto/acme/autocert"
)

type Vehicle struct {
	Id        ClientIdType
	Name      string
	Lat       float32
	Lon       float32
	Connected bool
	key       string // for decryption/encryption of heartbeats
}

func findVehicle(id ClientIdType, vehicles []Vehicle) *Vehicle {
	for idx, vehicle := range vehicles {
		if vehicle.Id == id {
			return &vehicles[idx]
		}
	}
	return nil
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

func main() {

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// TODO: store these in a database
	vehicles := []Vehicle{
		{"delivery_robot", "Delivery Robot", 52.14103951249229, 11.655338089964646, false, "e59d2738829ff3c344ebf3b904b7156368d604ed76ebe01a81d95d9257962d27"},
		{"cargo_bike", "Cargo Bike", 52.1402478934974, 11.646169343553602, false, "9847ab2a12410dc9aaf1ece0795932a90bfbf214c5755788930470781d42d797"},
		{"tugger_train", "Tugger Train", 52.143145559062944, 11.65555937689635, false, "d93947a0684c917a1d2006f382a69695e3b35b4336935e7ce7ca3347ae5b1339"},
	}

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

	// Serve static files
	fs := http.FileServer(http.Dir("./static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/index.html")
	})

	vehicleBroker := NewWebTransportBroker()

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

	type StatusMsg struct {
		Type     string
		Vehicles []Vehicle
	}

	occBroker := NewWebTransportBroker()
	statusMessage, _ := json.Marshal(StatusMsg{"status", vehicles})
	occBroker.updateStatus(statusMessage)

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

	// connect the two brokers
	type IncomingMsg struct {
		Recipient ClientIdType
	}
	go func() {
		for {
			select {
			case id := <-vehicleBroker.Connected:
				vehicle := findVehicle(id, vehicles)
				// TODO nil
				vehicle.Connected = true
				statusMessage, _ := json.Marshal(StatusMsg{"status", vehicles})
				occBroker.updateStatus(statusMessage)
			case id := <-vehicleBroker.Disconnected:
				vehicle := findVehicle(id, vehicles)
				// TODO nil
				vehicle.Connected = false
				statusMessage, _ := json.Marshal(StatusMsg{"status", vehicles})
				occBroker.updateStatus(statusMessage)
			case msg := <-vehicleBroker.Messages:
				result := IncomingMsg{}
				err := json.Unmarshal(msg.Payload, &result)
				if err != nil {
					log.Println("Received invalid message")
				}
				occBroker.sendMessage(result.Recipient, msg.Payload)
			case <-vehicleBroker.Datagrams:
			case <-occBroker.Connected:
			case <-occBroker.Disconnected:
			case <-occBroker.Messages:
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
	err := wtSrv.ListenAndServe()
	log.Fatal("HTTP/3 failed:", err)
}
