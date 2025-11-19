package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

const (
	certFile = "certs/server.crt"
	keyFile  = "certs/server.key"
)

// generateSelfSignedCert creates a new self-signed cert/key pair and saves them.
func generateSelfSignedCert() error {
	log.Println("🔏 Generating new self-signed TLS certificate...")

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	// Save certificate
	if err := os.MkdirAll("certs", 0700); err != nil {
		return err
	}
	certOut, _ := os.Create(certFile)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	certOut.Close()

	// Save private key
	keyOut, _ := os.Create(keyFile)
	b, _ := x509.MarshalECPrivateKey(priv)
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	keyOut.Close()

	log.Printf("✅ Saved cert: %s and key: %s\n", certFile, keyFile)
	return nil
}

func ensureCertExists() {
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		if err := generateSelfSignedCert(); err != nil {
			log.Fatalf("failed to generate cert: %v", err)
		}
	}
}

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

	ensureCertExists()

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("failed to load TLS cert: %v", err)
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
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
		srv.ListenAndServe()
	}()

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

		log.Println("Send")
		err = vehicleBroker.sendMessage(ClientIdType(recipient), bytes)
		log.Println("Send done")
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
				err = json.Unmarshal(msg.Payload, &result)
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
	err = wtSrv.ListenAndServe()
	log.Fatal("HTTP/3 failed:", err)
}
