package prio

import (
	"gopkg.in/dedis/onet.v1"
	"math/big"
	"gopkg.in/dedis/onet.v1/network"
	"unlynx/prio_utils"
	"unlynx/protocols"
)

const ServiceName = "Prio"


// ServiceResult will contain final results aggregation.
type ServiceResult struct {
	Results *big.Int
}

type DataSentClient struct {
	request *prio_utils.Request
	circuitConfig []int
	randomPoint *big.Int
}



func init() {
	onet.RegisterNewService(ServiceName, NewService)
	network.RegisterMessage(&DataSentClient{})
	network.RegisterMessage(&ServiceResult{})
}

type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor
	//
}


func NewService(c *onet.Context) onet.Service {
	newPrioInstance := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}

	return newPrioInstance
}

//this need to handle request sent by client meanign do the verification
//TODO : for aggregation do every x sec or do after x seconds ?
func (s *Service) Process(msg *network.Envelope) {
		tmp := (msg.Msg).(*DataSentClient)
		s.HandleRequest(tmp)
}

func (s *Service) HandleRequest(requestFromClient *DataSentClient) {
}
