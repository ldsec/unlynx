package serviceSkipchain

import (
	"gopkg.in/dedis/onet.v1"
	"time"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1/crypto"
	"gopkg.in/dedis/onet.v1/network"
	"gopkg.in/dedis/onet.v1/log"
	"github.com/JoaoAndreSa/MedCo/services"
	"github.com/JoaoAndreSa/MedCo/protocols"
	"github.com/dedis/cothority/cosi/protocol"
)

// ServiceName is the registered name for the skipchain topology service.
const ServiceName = "Topology"


//MESSAGES

// TopologyCreationQuery starts a new topology-skipchain with the initial data and asking all nodes in
// Roster to participate and sign before sending it to the skipchain cothority.
type TopologyCreationQuery struct {
	//Topology to be stored in the genesis block
	*StateTopology
	//If the message comes from a client or from a server
	IntraMessage bool
	//Conodes which have to participate in the creation of the topology skipchain
	Roster onet.Roster
}

// Service state is the response to the creation and update queries
type ServiceState struct {
	Error error
}

//STATE

// StateTopology represents the topology block to be added to the skipchain
type StateTopology struct {
	Data      DataTopology
	Signature crypto.SchnorrSig
	SignKey   abstract.Point
}

// DataTopology is used to store a particular network topology, composed by nodes and edges.
// Nodes represents Data Cothority servers and Data Providers.
type DataTopology struct {
	//Time of the creation of the skipblock, this information is added by the client.
	Time          time.Time
	DataCothority []DataCothority
	DataProviders []DataProvider
}

// DataCothority defines the group of the servers of the data cothority
type DataCothority struct {
	Aggregate abstract.Point
	Nodes     []Node
}

// DataProvider - for example an hospital
type DataProvider struct {
	Node
	Edges []network.Address
}

// Node - identifies a node of the network
type Node struct {
	Address     network.Address
	PublicKey   abstract.Point
	Description string
}

//SERVICE

// MsgTypes defines the Message Type ID for all the service's intra-messages.
type MsgTypes struct {
	msgTopologyCreationQuery network.MessageTypeID
}

var msgTypes = MsgTypes{}


func init() {
	onet.RegisterNewService(ServiceName, NewService)

	msgTypes.msgTopologyCreationQuery = network.RegisterMessage(&TopologyCreationQuery{})

	network.RegisterMessage(&ServiceState{})
}

// Service defines a service.
type Service struct {
	*onet.ServiceProcessor
}

// NewService constructor which registers the needed messages.
func NewService(c *onet.Context) onet.Service {
	newInstance := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	if cerr := newInstance.RegisterHandler(newInstance.HandleTopologyCreationQuery); cerr != nil {
		log.Fatal("Wrong Handler.", cerr)
	}

	c.RegisterProcessor(newInstance, msgTypes.msgTopologyCreationQuery)
	return newInstance
}

// Process implements the processor interface and is used to recognize messages broadcasted between servers
func (s *Service) Process(msg *network.Envelope) {
	if msg.MsgType.Equal(msgTypes.msgTopologyCreationQuery) {
		tmp := (msg.Msg).(*TopologyCreationQuery)
		s.HandleTopologyCreationQuery(tmp)
	}
}

// Query Handlers
//______________________________________________________________________________________________________________________

// HandleTopologyCreationQuery handles the reception of a topology creation query.
func (s *Service) HandleTopologyCreationQuery(recq *TopologyCreationQuery) (network.Message, onet.ClientError) {
	log.LLvl1(s.ServerIdentity(), "received a request for a new topology skipchain")

	if recq.IntraMessage==false{
		recq.IntraMessage = true

		err := services.SendISMOthers(s.ServiceProcessor, &recq.Roster, recq)
		if err != nil {
			log.Error("broadcasting error ", err)
		}

	}

	survey := castToSurvey(s.Survey.Get((string)(targetSurvey)))

	if len(survey.DpResponses) == 0 && len(survey.DpResponsesAggr) == 0 {
		log.LLvl1(s.ServerIdentity(), " no data to shuffle")
		return nil
	}

	pi, err := s.StartProtocol(protocols.ShufflingProtocolName, targetSurvey)
	if err != nil {
		return err
	}
	shufflingResult := <-pi.(*protocols.ShufflingProtocol).FeedbackChannel

	survey.PushShuffledProcessResponses(shufflingResult)
	s.Survey.Put(string(targetSurvey), survey)


	return err


	log.LLvl1(s.ServerIdentity(), "successfuly created a topology skipchain")
	return &ServiceState{Error: nil}, nil
}

// Protocol Handlers
//______________________________________________________________________________________________________________________

// NewProtocol creates a protocol instance executed by all nodes
func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	if tn.ProtocolName() != cosi.Name {
		log.Fatal("Shouldn't you be calling a cosi protocol")
	}

	tn.SetConfig(conf)

	pi, err := cosi.NewProtocol(tn)

	done := make(chan bool)
	// create the message we want to sign for this round
	msg := []byte("Hello World Cosi")

	// Register the function generating the protocol instance
	var root *cosi.CoSi
	// function that will be called when protocol is finished by the root
	doneFunc := func(sig []byte) {
		suite := hosts[0].Suite()
		publics := el.Publics()
		if err := root.VerifyResponses(aggPublic); err != nil {
			t.Fatal("Error verifying responses", err)
		}
		if err := VerifySignature(suite, publics, msg, sig); err != nil {
			t.Fatal("Error verifying signature:", err)
		}
		done <- true
	}

	// Start the protocol
	p, err := local.CreateProtocol("CoSi", tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}
	root = p.(*CoSi)
	root.Message = msg
	responseFunc := func(in []abstract.Scalar) {
		log.Lvl1("Got response")
		if len(root.Children()) != len(in) {
			t.Fatal("Didn't get same number of responses")
		}
	}
	root.RegisterResponseHook(responseFunc)
	root.RegisterSignatureHook(doneFunc)


	return pi, nil
}

// StartProtocol starts a specific protocol (Pipeline, Shuffling, etc.)
func (s *Service) StartProtocol(name string) (onet.ProtocolInstance, error) {
	tmp := castToSurvey(s.Survey.Get((string)(targetSurvey)))
	tree := tmp.Query.Roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())

	var tn *onet.TreeNodeInstance
	tn = s.NewTreeNodeInstance(tree, tree.Root, name)

	conf := onet.GenericConfig{Data: []byte(string(targetSurvey))}

	pi, err := s.NewProtocol(tn, &conf)
	if err != nil {
		log.Fatal("Error running" + name)
	}

	s.RegisterProtocolInstance(pi)
	go pi.Dispatch()
	go pi.Start()

	return pi, err
}
