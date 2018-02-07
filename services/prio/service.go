package prio

/**
This service instantiate a Prio Protocol, where DP awnser server querry. The part where a querier
ask server for data is not depicted. For each client submission, data are splitted, encoded
verified and aggregated.
We use the AFE of a sum directly implemented in prio_aggregation_protocol
but any other can be used.
*/

import (
	"github.com/fanliao/go-concurrentMap"
	"github.com/henrycg/prio/share"
	"github.com/henrycg/prio/triple"
	"github.com/henrycg/prio/utils"
	"github.com/lca1/unlynx/lib/prioUtils"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"math/big"

	"github.com/henrycg/prio/config"
	"github.com/lca1/unlynx/protocols/prio"
)

//ServiceName is the name for Prio Service
const ServiceName = "Prio"

// ServiceResult will contain final results aggregation.
type ServiceResult struct {
	Results string
}

//DataSentClient is the structure that the client send
type DataSentClient struct {
	Leader        *network.ServerIdentity
	Roster        *onet.Roster
	CircuitConfig []ConfigByte
	Key           utils.PRGKey
	RequestID     []byte
	RandomPoint   []byte
	Hint          [][]byte
	ShareA        []byte
	ShareB        []byte
	ShareC        []byte
}

//ExecRequest is the id of the request to execute
type ExecRequest struct {
	ID string
}

//ExecAgg is the id of the last request before aggregating
type ExecAgg struct {
	ID string
}

//AggResult is the result of an aggregation in bytes
type AggResult struct {
	Result []byte
}

//RequestResult is the empty structure used for verification response.
type RequestResult struct {
}

//MsgTypes is the type of message exchanged
type MsgTypes struct {
	msgProofDoing network.MessageTypeID
	msgProofExec  network.MessageTypeID
	msgAgg        network.MessageTypeID
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

//Service is the structure of the whole service
type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor
	//
	Request *concurrent.ConcurrentMap
	AggData [][]*big.Int
	Proto   *prio.PrioVerificationProtocol
	Count   int64
}

//NewService creates a new Prio Service.
func NewService(c *onet.Context) onet.Service {
	newPrioInstance := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		Request:          concurrent.NewConcurrentMap(),
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

//HandleRequest handles a request from a client by registering it
func (s *Service) HandleRequest(requestFromClient *DataSentClient) (network.Message, onet.ClientError) {

	if requestFromClient == nil {
		return nil, nil
	}

	s.Request.Put(string(requestFromClient.RequestID), requestFromClient)
	log.Lvl1(s.ServerIdentity(), " uploaded response data for Request ", string(requestFromClient.RequestID))

	return &ServiceResult{Results: string(requestFromClient.RequestID)}, nil
}

//ExecuteRequest executes the verification of a request
func (s *Service) ExecuteRequest(exe *ExecRequest) (network.Message, onet.ClientError) {

	//log.Lvl1(s.ServerIdentity(), " starts a Prio Verification Protocol")

	acc, err := s.VerifyPhase(exe.ID)
	if err != nil {
		log.Fatal("Error in the Verify Phase")
	}
	if !acc {
		log.LLvl2("Data have not been accepted for request ID", exe.ID)
	}
	//log.Lvl1("Finish verification")
	return nil, nil
}

//VerifyPhase is the verification phase of a request given it's ID
func (s *Service) VerifyPhase(requestID string) (bool, error) {
	tmp := castToRequest(s.Request.Get(requestID))
	isAccepted := false
	if s.ServerIdentity().Equal(tmp.Leader) {
		pi, err := s.StartProtocol(prio.PrioVerificationProtocolName, requestID)
		log.Lvl1(pi.(*prio.PrioVerificationProtocol).ServerIdentity())

		if err != nil {
			return isAccepted, err
		}

	}

	cothorityAggregatedData := <-s.Proto.AggregateData
	if len(cothorityAggregatedData) > 0 {
		s.Count++
		isAccepted = true
	}
	s.AggData = append(s.AggData, cothorityAggregatedData)

	return isAccepted, nil
}

//ExecuteAggregation aggregates if you have more than 2 datas
func (s *Service) ExecuteAggregation(exe *ExecAgg) (network.Message, onet.ClientError) {
	pi, err := s.StartProtocol(prio.PrioAggregationProtocolName, exe.ID)

	if err != nil {
		log.Fatal("Error in the Aggregation Phase")
	}
	if len(pi.(*prio.PrioAggregationProtocol).Shares) >= 2 {
		aggRes := <-pi.(*prio.PrioAggregationProtocol).Feedback
		return &AggResult{aggRes[0].Bytes()}, nil
	}

	log.Lvl2("You cannot aggregate less than 5 data points")
	return &AggResult{[]byte{byte(0)}}, nil

}

//StartProtocol creates a protocol given the name
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

//NewProtocol create a new Protocol given a protocol name
func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {

	tn.SetConfig(conf)
	var pi onet.ProtocolInstance
	var err error

	//target := string(string(conf.Data))
	request := castToRequest(s.Request.Get(string(conf.Data)))

	switch tn.ProtocolName() {
	case prio.PrioVerificationProtocolName:
		pi, err = prio.NewPrioVerifcationProtocol(tn)

		circConf := make([]*config.Field, 0)
		for i := 0; i < len(request.CircuitConfig); i++ {
			linReg := make([]int, 0)
			for j := 0; j < len(request.CircuitConfig[i].LinRegBits); j++ {
				linReg = append(linReg, int(request.CircuitConfig[i].LinRegBits[j]))
			}
			circConf = append(circConf, &config.Field{Name: request.CircuitConfig[i].Name, Type: config.FieldType(request.CircuitConfig[i].Type), IntBits: int(request.CircuitConfig[i].IntBits), LinRegBits: linReg, IntPow: int(request.CircuitConfig[i].IntPow), CountMinBuckets: int(request.CircuitConfig[i].CountMinBuckets), CountMinHashes: int(request.CircuitConfig[i].CountMinHashes)})
		}
		ckt := prioUtils.ConfigToCircuit(circConf)

		tripleShareReq := new(triple.Share)
		tripleShareReq.ShareA = big.NewInt(0).SetBytes(request.ShareA)
		tripleShareReq.ShareB = big.NewInt(0).SetBytes(request.ShareB)
		tripleShareReq.ShareC = big.NewInt(0).SetBytes(request.ShareC)

		hintReq := new(share.PRGHints)
		hintReq.Key = request.Key
		hintReq.Delta = make([]*big.Int, 0)
		for _, v := range request.Hint {
			hintReq.Delta = append(hintReq.Delta, big.NewInt(0).SetBytes(v))
		}

		protoReq := prioUtils.Request{RequestID: request.RequestID, TripleShare: tripleShareReq, Hint: hintReq}
		pi.(*prio.PrioVerificationProtocol).Request = &protoReq
		pi.(*prio.PrioVerificationProtocol).Checker = prioUtils.NewChecker(ckt, tn.Index(), 0)
		pi.(*prio.PrioVerificationProtocol).Pre = prioUtils.NewCheckerPrecomp(ckt)
		rdm := big.NewInt(0).SetBytes(request.RandomPoint)
		pi.(*prio.PrioVerificationProtocol).Pre.SetCheckerPrecomp(rdm)
		s.Proto = pi.(*prio.PrioVerificationProtocol)

		if err != nil {
			log.Lvl1("Error")
			return nil, err
		}

	case prio.PrioAggregationProtocolName:
		pi, err = prio.NewPrioAggregationProtocol(tn)

		pi.(*prio.PrioAggregationProtocol).Modulus = share.IntModulus
		pi.(*prio.PrioAggregationProtocol).Shares = s.AggData
		if err != nil {
			log.Lvl1("Error")
			return nil, err
		}

	}
	return pi, err
}
