package UnlynxRange

import (
	"gopkg.in/dedis/onet.v1"
	"github.com/fanliao/go-concurrentMap"
	"gopkg.in/dedis/onet.v1/network"
	"gopkg.in/dedis/onet.v1/log"
	"unlynx/lib"
	"gopkg.in/dedis/crypto.v0/abstract"
	"github.com/dedis/paper_17_dfinity/pbc"
	"github.com/lca1/unlynx/protocols"
	//this import are here because some modfi added in local
	lib2 "github.com/lca1/unlynx/lib"
	proto2 "unlynx/protocols"
	"errors"
)

const ServiceName = "UnlynxRange"
//Structs _______________________________________________________________________________________________
type PublishSignatureByte struct {
	Public abstract.Point
	Signature [][]byte
}

type DataDP struct {
	ClientPublic abstract.Point
	CAPublic	abstract.Point
	RequestID []byte
}

type ServiceSig struct {
	PublicCA abstract.Point
	RequestID []byte
	Signature PublishSignatureByte
	U 			int64
	L			int64
}


type ResultStored struct {
	Roster *onet.Roster
	Ciphers lib2.CipherText
}
//messages_________________________________________________________________________________________________
//The type of message exchanged
type MsgTypes struct {
	msgSig network.MessageTypeID
	msgProof network.MessageTypeID
}

var msgTypes = MsgTypes{}

func init() {
	onet.RegisterNewService(ServiceName, NewService)
	msgTypes.msgSig = network.RegisterMessage(&DataDP{})
	msgTypes.msgProof = network.RegisterMessage(&StructProofRangeByte{})

	network.RegisterMessage(&ServiceSig{})
	network.RegisterMessage(&lib.PublishRangeProof{})
	network.RegisterMessage(&VerifResult{})
}

//The service strucute
type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor
	CAPublic	abstract.Point
	//Client (the querrier) public key for KeySwitch
	ClientPub	abstract.Point
	//
	Signatures PublishSignatureByte
	Request *concurrent.ConcurrentMap
	AggData map[lib2.GroupingKey]lib2.FilteredResponse
	U int64
	L int64
	Count int64
}

func NewService(c *onet.Context) onet.Service {
	newUnlynxRange := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		Request: concurrent.NewConcurrentMap(),
		Count: 0,
	}


	if cerr := newUnlynxRange.RegisterHandler(newUnlynxRange.HandleRequest); cerr != nil {
		log.Fatal("Wrong Handler.", cerr)
	}

	if cerr := newUnlynxRange.RegisterHandler(newUnlynxRange.ExecuteProof); cerr != nil {
		log.Fatal("Wrong Handler.", cerr)
	}

	//Let's say range are already known
	newUnlynxRange.U = int64(2)
	newUnlynxRange.L = int64(6)
	//Compute the signatures in bytes so that you can send them

	return newUnlynxRange
}

//Handle a request from a client by registering it and computing each the hash and sending them
func (s *Service) HandleRequest(requestFromDP *DataDP)(network.Message, onet.ClientError) {

	if requestFromDP == nil {
		return nil, nil
	}
	//every service has the samee Public key
	s.CAPublic = requestFromDP.CAPublic
	if(requestFromDP.ClientPublic != nil) {
		s.ClientPub = requestFromDP.ClientPublic
	}

	signature := lib.InitRangeProofSignature(s.U)
	sigStruct := PublishSignatureByte{Public: signature.Public, Signature: make([][]byte, len(signature.Signature))}
	for i := 0; i < len(signature.Signature); i++ {
		bin,err := signature.Signature[i].MarshalBinary()

		if err != nil {
			log.Lvl1("Error in serializing ", err)
		}

		sigStruct.Signature[i] = bin
	}

	s.Signatures = sigStruct

	return &ServiceSig{RequestID:requestFromDP.RequestID,U:s.U,L:s.L,Signature:s.Signatures,PublicCA:s.CAPublic},nil
}

// execute the proof validation. If number of request executed pass a threshold
//We launch aggregation and key switch
func (s *Service)ExecuteProof(proofFromDP *StructProofRangeByte)(network.Message, onet.ClientError){

	pairing := pbc.NewPairingFp254BNb()
	parameterToValidate := lib.PublishRangeProof{Zv:proofFromDP.Zv,D:proofFromDP.D,Zr:proofFromDP.Zr,Challenge:proofFromDP.Challenge,Cipher:proofFromDP.Commit,Zphi:proofFromDP.Zphi}
	V,A := make([]abstract.Point,len(proofFromDP.V)),make([]abstract.Point,len(proofFromDP.A))


	for i:=0 ; i<len(proofFromDP.V); i++ {
		pointV := pairing.G1().Point().Null()
		pointA := pairing.GT().Point().Null()
		err := pointV.UnmarshalBinary(proofFromDP.V[i])

		V[i] = pointV

		if err != nil {
			log.Fatal("Error in desesiralizing")
		}

		err = pointA.UnmarshalBinary(proofFromDP.A[i])
		if err != nil {
			log.Fatal("Error in desesiralizing")
		}

		A[i] = pointA
	}
	parameterToValidate.A = A
	parameterToValidate.V = V

	//verification of the result received
	res := VerifResult{}
	if((lib.RangeProofVerification(parameterToValidate,s.U,s.L,s.Signatures.Public,s.CAPublic))) {
		res.Res = 0
		s.Count++
	} else {
		log.Lvl1("One result was false")
		res.Res = 1
	}

	//If the cipher was originaly for this server save it on the server, else discard
	if(proofFromDP.EntryPoint){
		s.Request.Put(proofFromDP.RequestID,&ResultStored{Ciphers:parameterToValidate.Cipher,Roster:proofFromDP.Roster})
		//if you have more than x datas, aggregate, change as you wish (in function of # clients
		if(s.Count>=10) {
			log.Lvl1("Launch Service")
			s.StartService(proofFromDP.RequestID, true)
		}
	}

	return &res,nil
}

//Start the service aggregation + key switch
func (s *Service) StartService(targetDataID string, root bool) error {

	if root == true {
		start := lib.StartTimer(s.ServerIdentity().String() + "_AggregationPhase")
		err := s.AggregationPhase(targetDataID)
		if err != nil {
			log.Fatal("Error in the Aggregation Phase")
		}

		lib.EndTimer(start)
	}

	if root == true {
		start := lib.StartTimer(s.ServerIdentity().String() + "_KeySwitchingPhase")

		s.KeySwitchingPhase(targetDataID)

		lib.EndTimer(start)
	}

	return nil
}

func (s *Service) StartProtocol(name string, targetData string) (onet.ProtocolInstance, error) {

	tmp := castToData(s.Request.Get((string)(targetData)))
	tree := tmp.Roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())

	var tn *onet.TreeNodeInstance
	tn = s.NewTreeNodeInstance(tree, tree.Root, name)

	conf := onet.GenericConfig{Data: []byte(string(targetData))}
	pi, err := s.NewProtocol(tn, &conf)
	if err != nil {
		log.Fatal("Error running" + name , err)
	}

	s.RegisterProtocolInstance(pi)
	go pi.Dispatch()
	go pi.Start()

	return pi, err
}

func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	tn.SetConfig(conf)
	var pi onet.ProtocolInstance
	var err error

	switch tn.ProtocolName() {
	case protocols.CollectiveAggregationProtocolName:
		pi, err = protocols.NewCollectiveAggregationProtocol(tn)
		if err != nil {
			return nil, err
		}
		// waits for all other nodes to finish the tagging phase
		target := castToData(s.Request.Get(string(conf.Data)))
		if err != nil {
			log.Lvl1("No data exist ", err)
		}

		log.Lvl1(target)
		testCVMap := make(map[lib2.GroupingKey]lib2.FilteredResponse)
		if(target != nil) {
			vec := []lib2.CipherText{target.Ciphers}
			testCVMap["T"] = lib2.FilteredResponse{GroupByEnc: nil, AggregatingAttributes: vec}
		}

		pi.(*protocols.CollectiveAggregationProtocol).GroupedData = &testCVMap
		pi.(*protocols.CollectiveAggregationProtocol).Proofs = true

	case proto2.KeySwitchingNoByteProtocolName:
		pi, err = proto2.NewKeySwitchingNoByteProtocol(tn)
		if err != nil {
			return nil, err
		}
		keySwitch := pi.(*proto2.KeySwitchingNoByteProtocol)
		keySwitch.Proofs = true
		if tn.IsRoot() {
			coaggr := []lib2.FilteredResponse{}

			coaggr = s.getAggr(false,lib2.CipherText{})

			keySwitch.TargetOfSwitch = &coaggr
//			tmp := survey.Query.ClientPubKey
			keySwitch.TargetPublicKey = &s.ClientPub

		}
	default:
		return nil, errors.New("Service attempts to start an unknown protocol: " + tn.ProtocolName() + ".")
	}

	return pi,err
}


func (s *Service) AggregationPhase(targetID string)(error) {

	pi, err := s.StartProtocol(protocols.CollectiveAggregationProtocolName, targetID)
	if err != nil {
		return err
	}


	cothorityAggregatedData := <-pi.(*protocols.CollectiveAggregationProtocol).FeedbackChannel
	s.AggData = cothorityAggregatedData.GroupedData
	return nil
}

func (s *Service) KeySwitchingPhase(targetID string) error {

	pi, err := s.StartProtocol(proto2.KeySwitchingNoByteProtocolName, targetID)
	if err != nil {
		return err
	}
	keySwitchedAggregatedResponses := <-pi.(*proto2.KeySwitchingNoByteProtocol).FeedbackChannel

	log.Lvl1(keySwitchedAggregatedResponses)
	return err
}

func castToData(object interface{}, err error) *ResultStored {
	if err != nil {
		log.Fatal("Error reading map")
	}
	if object == nil {
		return nil
	}
	return object.(*ResultStored)
}


func (s *Service) getAggr(diffPri bool, noise lib2.CipherText) []lib2.FilteredResponse {
	aggregatedResults := make([]lib2.FilteredResponse, len(s.AggData))
	count := 0

	for _, value := range s.AggData {
		aggregatedResults[count] = value
		count++
	}

	//GroupedDeterministicFilteredResponses = make(map[lib2.GroupingKey]lib2.FilteredResponse)

	if diffPri == true {
		for _, v := range aggregatedResults {
			for _, aggr := range v.AggregatingAttributes {
				aggr.Add(aggr, noise)
			}
		}
	}

	return aggregatedResults
}