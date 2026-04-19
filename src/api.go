package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"

	"gorm.io/gorm"
)

type VehicleStore struct {
	mu            sync.RWMutex
	vehicles      map[ClientIdType]*Vehicle
	db            *gorm.DB
	occBroker     *WebtransportBroker
	vehicleBroker *WebtransportBroker
}

// snapshot returns a slice copy of all vehicles, safe to use after releasing the lock.
// Caller must hold at least a read lock.
func (s *VehicleStore) snapshot() []Vehicle {
	result := make([]Vehicle, 0, len(s.vehicles))
	for _, v := range s.vehicles {
		result = append(result, *v)
	}
	return result
}

func (s *VehicleStore) broadcastStatus() {
	s.mu.RLock()
	snap := s.snapshot()
	s.mu.RUnlock()

	statusMessage, _ := json.Marshal(StatusMsg{"status", snap})
	s.occBroker.updateStatus(statusMessage)
}

// RegisterAPIRoutes adds REST endpoints to the mux.
func RegisterAPIRoutes(mux *http.ServeMux, store *VehicleStore) {
	mux.HandleFunc("/api/vehicles", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetVehicles(w, r, store)
		case http.MethodPost:
			handleAddVehicle(w, r, store)
		case http.MethodOptions:
			handleCORS(w)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/vehicles/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodDelete:
			handleDeleteVehicle(w, r, store)
		case http.MethodOptions:
			handleCORS(w)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

func setCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*") // TODO: restrict in production
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

func handleCORS(w http.ResponseWriter) {
	setCORS(w)
	w.WriteHeader(http.StatusNoContent)
}

func handleGetVehicles(w http.ResponseWriter, r *http.Request, store *VehicleStore) {
	setCORS(w)
	store.mu.RLock()
	snap := store.snapshot()
	store.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snap)
}

type AddVehicleRequest struct {
	Id   string  `json:"Id"`
	Name string  `json:"Name"`
	Lat  float64 `json:"Lat"`
	Lon  float64 `json:"Lon"`
}

func handleAddVehicle(w http.ResponseWriter, r *http.Request, store *VehicleStore) {
	setCORS(w)
	// TODO: auth
	var req AddVehicleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Id == "" || req.Name == "" {
		http.Error(w, "Id and Name are required", http.StatusBadRequest)
		return
	}

	v := &Vehicle{
		Id:   ClientIdType(req.Id),
		Name: req.Name,
		Lat:  req.Lat,
		Lon:  req.Lon,
	}

	if err := InsertVehicle(store.db, v); err != nil {
		log.Printf("Failed to insert vehicle: %v", err)
		http.Error(w, "Failed to add vehicle", http.StatusInternalServerError)
		return
	}

	store.mu.Lock()
	store.vehicles[v.Id] = v
	store.mu.Unlock()

	store.broadcastStatus()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(v)
}

func handleDeleteVehicle(w http.ResponseWriter, r *http.Request, store *VehicleStore) {
	setCORS(w)
	// TODO: auth
	// Extract ID from /api/vehicles/{id}
	id := ClientIdType(strings.TrimPrefix(r.URL.Path, "/api/vehicles/"))
	if id == "" {
		http.Error(w, "Vehicle ID is required", http.StatusBadRequest)
		return
	}

	if err := DeleteVehicle(store.db, id); err != nil {
		log.Printf("Failed to delete vehicle: %v", err)
		http.Error(w, "Vehicle not found", http.StatusNotFound)
		return
	}

	// Close active WebTransport session if vehicle is connected
	store.vehicleBroker.CloseSession(id)

	store.mu.Lock()
	delete(store.vehicles, id)
	store.mu.Unlock()

	store.broadcastStatus()

	w.WriteHeader(http.StatusNoContent)
}
