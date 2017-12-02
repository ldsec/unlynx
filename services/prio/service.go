package prio

import (
	"gopkg.in/dedis/onet.v1"
	"math/big"
	"gopkg.in/dedis/onet.v1/network"
	"unlynx/prio_utils"
	"unlynx/protocols"
	"gopkg.in/dedis/onet.v1/log"
	"github.com/fanliao/go-concurrentMap"
)

const ServiceName = "Prio"

var tree *onet.Tree
var root *network.ServerIdentity = nil


// ServiceResult will contain final results aggregation.
type ServiceResult struct {
	Results string
}

type DataSentClient struct {
	Leader *network.ServerIdentity
	Roster *onet.Roster
	Request *prio_utils.Request
	CircuitConfig []int64
	RandomPoint []byte
}

type ExecRequest struct {
	ID string

}

type RequestResult struct {

}
type MsgTypes struct {
	msgProofDoing network.MessageTypeID
	msgProofExec network.MessageTypeID
}

var msgTypes = MsgTypes{}

func init() {
	onet.RegisterNewService(ServiceName, NewService)
	msgTypes.msgProofDoing = network.RegisterMessage(&DataSentClient{})
	msgTypes.msgProofExec = network.RegisterMessage(&ExecRequest{})
	network.RegisterMessage(&ServiceResult{})
}

type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor
	//
	Request *concurrent.ConcurrentMap
	aggData [][]*big.Int
}


func NewService(c *onet.Context) onet.Service {
	newPrioInstance := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		Request: concurrent.NewConcurrentMap(),
	}

	if cerr := newPrioInstance.RegisterHandler(newPrioInstance.HandleRequest); cerr != nil {
		log.Fatal("Wrong Handler.", cerr)
	}


	if cerr := newPrioInstance.RegisterHandler(newPrioInstance.ExecuteRequest); cerr != nil {
		log.Fatal("Wrong Handler.", cerr)
	}

	return newPrioInstance
}

//this need to handle request sent by client meanign do the verification
//TODO : for aggregation do every x sec or do after x seconds ?

func (s *Service) HandleRequest(requestFromClient *DataSentClient)(network.Message, onet.ClientError) {

	//log.Lvl1(requestFromClient)
	//log.Lvl1(s.ServerIdentity())

	if requestFromClient == nil {
		return nil, nil
	}

	s.Request.Put(string(requestFromClient.Request.RequestID),requestFromClient)
	log.Lvl1(s.ServerIdentity(), " uploaded response data for survey ", requestFromClient.Request.RequestID)


	return &ServiceResult{Results:string(requestFromClient.Request.RequestID)},nil
}

func (s *Service) ExecuteRequest(exe *ExecRequest)(network.Message, onet.ClientError) {
	//req := castToRequest(s.Request.Get(exe.ID))
	log.Lvl1(s.ServerIdentity(), " starts a Prio Protocol")

	err := s.VerifyPhase(exe.ID)
	if err != nil {
		log.Fatal("Error in the Shuffling Phase")
	}
	log.Lvl1("Finish")
	return nil,nil
}

func (s *Service) VerifyPhase(requestID string) (error) {
	pi, err := s.StartProtocol(protocols.PrioVerificationProtocolName,requestID )
	if err != nil {
		return err
	}
	cothorityAggregatedData := <-pi.(*protocols.PrioVerificationProtocol).AggregateData

	log.Lvl1(cothorityAggregatedData)
	return nil
}

func (s *Service) StartProtocol(name string, targetRequest string) (onet.ProtocolInstance, error) {
	tmp := castToRequest(s.Request.Get((string)(targetRequest)))


	tree := tmp.Roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())

	var tn *onet.TreeNodeInstance
	tn = s.NewTreeNodeInstance(tree, tree.Root, name)

	conf := onet.GenericConfig{Data: []byte(string(targetRequest))}

	pi, err := s.NewProtocol(tn, &conf)
	if err != nil {
		log.Fatal("Error running" + name)
	}

	s.RegisterProtocolInstance(pi)
	go pi.Dispatch()
	go pi.Start()

	return pi, err
}



func castToRequest(object interface{}, err error) *DataSentClient {
	if err != nil {
		log.Fatal("Error reading map")
	}
	return object.(*DataSentClient)
}

func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	tn.SetConfig(conf)
	var pi onet.ProtocolInstance
	var err error

	//target := string(string(conf.Data))
	request := castToRequest(s.Request.Get(string(conf.Data)))

	switch tn.ProtocolName() {
	case protocols.PrioVerificationProtocolName:
		pi, err = protocols.NewPrioVerifcationProtocol(tn)

		ckt := prio_utils.ConfigToCircuitBit(request.CircuitConfig)
		pi.(*protocols.PrioVerificationProtocol).Request = request.Request
		pi.(*protocols.PrioVerificationProtocol).Checker = prio_utils.NewChecker(ckt,tn.Index(),0)
		pi.(*protocols.PrioVerificationProtocol).Pre = prio_utils.NewCheckerPrecomp(ckt)
		pi.(*protocols.PrioVerificationProtocol).Pre.SetCheckerPrecomp(big.NewInt(0).SetBytes(request.RandomPoint))
		if err != nil {
			log.Lvl1("Error")
			return nil, err
		}

	case protocols.PrioAggregationProtocolName:
		pi, err = protocols.NewPrioAggregationProtocol(tn)
		if err != nil {
			log.Lvl1("Error")
			return nil, err
		}

	}
	return pi,err
}

