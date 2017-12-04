package prio

import (
	"gopkg.in/dedis/onet.v1"
	"math/big"
	"gopkg.in/dedis/onet.v1/network"
	"unlynx/prio_utils"
	"unlynx/protocols"
	"gopkg.in/dedis/onet.v1/log"
	"github.com/fanliao/go-concurrentMap"
	"github.com/henrycg/prio/utils"
	"github.com/henrycg/prio/triple"
	"github.com/henrycg/prio/share"
)

const ServiceName = "Prio"

// ServiceResult will contain final results aggregation.
type ServiceResult struct {
	Results string
}

//structure that the client send
type DataSentClient struct {
	Leader *network.ServerIdentity
	Roster *onet.Roster
	CircuitConfig []int64
	Key   utils.PRGKey
	RequestID []byte
	RandomPoint []byte
	Hint [][]byte
	ShareA []byte
	ShareB []byte
	ShareC []byte
}

type ExecRequest struct {
	ID string

}

type ExecAgg struct {
	ID string
}

type AggResult struct {
	Result []byte
}

type RequestResult struct {

}
type MsgTypes struct {
	msgProofDoing network.MessageTypeID
	msgProofExec network.MessageTypeID
	msgAgg network.MessageTypeID
}

var msgTypes = MsgTypes{}

func init() {
	onet.RegisterNewService(ServiceName, NewService)
	msgTypes.msgProofDoing = network.RegisterMessage(&DataSentClient{})
	msgTypes.msgProofExec = network.RegisterMessage(&ExecRequest{})
	msgTypes.msgAgg = network.RegisterMessage(ExecAgg{})
	network.RegisterMessage(&ServiceResult{})
	network.RegisterMessage(&AggResult{})
}

type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor
	//
	Request *concurrent.ConcurrentMap
	aggData [][]*big.Int
	Test *protocols.PrioVerificationProtocol
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

	if cerr := newPrioInstance.RegisterHandler(newPrioInstance.ExecuteAggregation); cerr != nil {
		log.Fatal("Wrong Handler.", cerr)
	}


	return newPrioInstance
}

//this need to handle request sent by client meanign do the verification
//TODO : for aggregation do every x sec or do after x seconds ?

func (s *Service) HandleRequest(requestFromClient *DataSentClient)(network.Message, onet.ClientError) {

	if requestFromClient == nil {
		return nil, nil
	}

	s.Request.Put(string(requestFromClient.RequestID),requestFromClient)
	log.Lvl1(s.ServerIdentity(), " uploaded response data for Request ", string(requestFromClient.RequestID))


	return &ServiceResult{Results:string(requestFromClient.RequestID)},nil
}

func (s *Service) ExecuteRequest(exe *ExecRequest)(network.Message, onet.ClientError) {
	//req := castToRequest(s.Request.Get(exe.ID))
	log.Lvl1(s.ServerIdentity(), " starts a Prio Verification Protocol")

	err := s.VerifyPhase(exe.ID)
	if err != nil {
		log.Fatal("Error in the Verify Phase")
	}
	log.Lvl1("Finish verification")
	return nil,nil
}

func (s *Service) VerifyPhase(requestID string) (error) {
	tmp := castToRequest(s.Request.Get(requestID))

	if(s.ServerIdentity().Equal(tmp.Leader)) {
		pi, err := s.StartProtocol(protocols.PrioVerificationProtocolName,requestID )
		log.Lvl1(pi)
		if err != nil {
			return err
		}
	}

	cothorityAggregatedData := <- s.Test.AggregateData
	s.aggData = append(s.aggData, cothorityAggregatedData)
	//log.Lvl1(s.aggData)

	return nil
}

func (s *Service) ExecuteAggregation(exe *ExecAgg)(network.Message, onet.ClientError) {
	pi, err := s.StartProtocol(protocols.PrioAggregationProtocolName, exe.ID )

	if err != nil {
		log.Fatal("Error in the Aggregation Phase")
	}
	log.Lvl1(<-pi.(*protocols.PrioAggregationProtocol).Feedback)
	return nil,nil
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

		tripleShareReq := new(triple.Share)
		tripleShareReq.ShareA = big.NewInt(0).SetBytes(request.ShareA)
		tripleShareReq.ShareB = big.NewInt(0).SetBytes(request.ShareB)
		tripleShareReq.ShareC = big.NewInt(0).SetBytes(request.ShareC)

		hintReq := new(share.PRGHints)
		hintReq.Key = request.Key
		hintReq.Delta = make([]*big.Int,0)
		for _,v := range request.Hint {
			hintReq.Delta = append(hintReq.Delta,big.NewInt(0).SetBytes(v))
		}

		protoReq := prio_utils.Request{RequestID:request.RequestID,TripleShare:tripleShareReq,Hint:hintReq}
		pi.(*protocols.PrioVerificationProtocol).Request = &protoReq
		pi.(*protocols.PrioVerificationProtocol).Checker = prio_utils.NewChecker(ckt,tn.Index(),0)
		pi.(*protocols.PrioVerificationProtocol).Pre = prio_utils.NewCheckerPrecomp(ckt)
		rdm := big.NewInt(0).SetBytes(request.RandomPoint)
		pi.(*protocols.PrioVerificationProtocol).Pre.SetCheckerPrecomp(rdm)
		s.Test = pi.(*protocols.PrioVerificationProtocol)

		if err != nil {
			log.Lvl1("Error")
			return nil, err
		}

	case protocols.PrioAggregationProtocolName:
		pi, err = protocols.NewPrioAggregationProtocol(tn)

		pi.(*protocols.PrioAggregationProtocol).Modulus = share.IntModulus
		shares := make([]*big.Int,0)
		for _,v := range s.aggData {
			for _,u := range v {
				shares = append(shares,u)
			}
		}
		pi.(*protocols.PrioAggregationProtocol).Shares = shares
		if err != nil {
			log.Lvl1("Error")
			return nil, err
		}

	}
	return pi,err
}

