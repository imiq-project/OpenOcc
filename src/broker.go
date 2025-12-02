package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/quic-go/webtransport-go"
)

type ClientIdType string

type WebTransportClient struct {
	session    *webtransport.Session
	stream     *webtransport.Stream
	writeMutex sync.Mutex
}

type BrokerMessage struct {
	Sender  ClientIdType
	Payload []byte
}

type WebtransportBroker struct {
	clients       sync.Map
	statusMessage []byte
	Messages      chan BrokerMessage
	Datagrams     chan BrokerMessage
	Connected     chan ClientIdType
	Disconnected  chan ClientIdType
}

func NewWebTransportBroker() WebtransportBroker {
	return WebtransportBroker{
		Messages:      make(chan BrokerMessage),
		Datagrams:     make(chan BrokerMessage),
		Connected:     make(chan ClientIdType),
		Disconnected:  make(chan ClientIdType),
		statusMessage: make([]byte, 0),
	}
}

func (h *WebtransportBroker) updateStatus(msg []byte) {
	h.statusMessage = msg
	// TODO: mutex
	if len(h.statusMessage) > 0 {
		h.broadcast("", msg)
	}
}

func writeAll(msg []byte, stream *webtransport.Stream) error {
	startIdx := 0
	// TODO: ensure that msg does not contain \0
	msg = append(msg, 0) // delimiter
	for {
		if startIdx >= len(msg) {
			break
		}
		n, err := stream.Write(msg[startIdx:])
		if err != nil {
			return err
		}
		startIdx += n
	}
	return nil
}

func (h *WebtransportBroker) broadcast(sender ClientIdType, message []byte) {
	h.clients.Range(func(key, value any) bool {
		id := key.(ClientIdType)
		client := value.(*WebTransportClient)
		if id != sender {
			client.writeMutex.Lock()
			err := writeAll(message, client.stream)
			client.writeMutex.Unlock()
			if err != nil {
				log.Println("Write error", err)
				client.session.CloseWithError(0, "")
				h.clients.Delete(key)
				h.Disconnected <- id
			}
		}
		return true
	})
}

func (h *WebtransportBroker) sendMessage(recipient ClientIdType, payload []byte) error {
	value, ok := h.clients.Load(recipient)
	if ok == false {
		return fmt.Errorf("invalid recipient %s", recipient)
	}
	client := value.(*WebTransportClient)
	client.writeMutex.Lock()
	err := writeAll(payload, client.stream)
	client.writeMutex.Unlock()
	return err
}

func (h *WebtransportBroker) sendDatagram(recipient ClientIdType, payload []byte) error {
	client, ok := h.clients.Load(recipient)
	if !ok {
		return fmt.Errorf("invalid recipient %s", recipient)
	}
	err := client.(*WebTransportClient).session.SendDatagram(payload)
	return err
}

func (h *WebtransportBroker) HandleSession(clientId ClientIdType, session *webtransport.Session) {
	if clientId == "" {
		log.Println("Client id cannot be empty!")
		return
	}
	log.Println("New session", session.RemoteAddr())
	stream, err := session.AcceptStream(context.Background())
	if err != nil {
		log.Println("session closed:", err)
		return
	}
	defer stream.Close()
	defer session.CloseWithError(0, "")

	client := &WebTransportClient{session, stream, sync.Mutex{}}
	previous, existed := h.clients.Swap(clientId, client)
	if existed {
		log.Println("Closing existing session")
		previousClient := previous.(*WebTransportClient)
		previousClient.stream.CancelRead(0)
		previousClient.stream.CancelWrite(0)
		previousClient.session.CloseWithError(0, "")
	}
	h.Connected <- clientId
	log.Println("New client connected", clientId, session.RemoteAddr())

	if len(h.statusMessage) > 0 {
		client.writeMutex.Lock()
		writeAll(h.statusMessage, stream)
		client.writeMutex.Unlock()
	}

	go func() {
		for {
			data, err := session.ReceiveDatagram(context.Background())
			if err != nil {
				log.Println("Datagram error:", err)
				// we remove the client below
				break
			}
			h.Datagrams <- BrokerMessage{clientId, data}
		}
	}()

	stream.SetReadDeadline(time.Time{}) // no timeout
	buffer := make([]byte, 0)
	for {
		data := make([]byte, 1024)
		n, err := stream.Read(data)
		if err != nil {
			log.Println("Read error:", err)
			var streamErr *webtransport.StreamError
			if errors.As(err, &streamErr) && !streamErr.Remote {
				log.Println("We closed the stream, client already removed")
			} else {
				log.Println("Remove client", clientId, session.RemoteAddr())
				h.clients.Delete(clientId)
				h.Disconnected <- clientId
			}
			break
		}
		for _, i := range data[:n] {
			if i != 0 {
				buffer = append(buffer, i)
			} else {
				h.Messages <- BrokerMessage{clientId, buffer[:]}
				buffer = make([]byte, 0)
			}
		}
	}
}
