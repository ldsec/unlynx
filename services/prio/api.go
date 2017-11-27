package prio

import (
	"gopkg.in/dedis/onet.v1/network"
	"gopkg.in/dedis/onet.v1"
)

type API struct {
	*onet.Client
	ClientID   string
	entryPoint *network.ServerIdentity
}

// NewPrioClient constructor of a client.
func NewPrioClient(entryPoint *network.ServerIdentity, clientID string) *API {

	newClient := &API{
		Client:     onet.NewClient(ServiceName),
		ClientID:   clientID,
		entryPoint: entryPoint,
	}
	return newClient
}
