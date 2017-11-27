package prio

import (
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
	"github.com/fanliao/go-concurrentMap"
	"sync"
)

const ServiceName = "Prio"


func init() {
	onet.RegisterNewService(ServiceName, NewService)
}

type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor

}


func NewService(c *onet.Context) onet.Service {
	newPrioInstance := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),

	}

	return newPrioInstance
}

// NewProtocol creates a protocol instance executed by all nodes
func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	tn.SetConfig(conf)

	var pi onet.ProtocolInstance
	var err error

	return nil,nil
}
