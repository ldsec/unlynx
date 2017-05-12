package serviceSkipchain

import (
	"gopkg.in/dedis/onet.v1"
	"time"
	"gopkg.in/dedis/onet.v1/network"
	"gopkg.in/dedis/onet.v1/log"
	"github.com/dedis/cothority/cosi/protocol"
	"gopkg.in/dedis/onet.v1/crypto"
	"medblock/service/topology"
)

// ServiceName is the registered name for the skipchain topology service.
const ServiceName = "Topology"


//MESSAGES

// TopologyCreationQuery starts a new topology-skipchain with the initial data and asking all nodes in
// Roster to participate and sign before sending it to the skipchain cothority.
type TopologyCreationQuery struct {
	//Topology to be stored in the genesis block
	*topology.StateTopology
	//If the message comes from a client or from a server
	IntraMessage bool
	//Conodes which have to participate in the creation of the topology skipchain
	Roster onet.Roster
}

// Service state is the response to the different api requests
type ServiceState struct {}

// SignatureResponse is what the Cosi protocol will reply to clients.
type SignatureResponse struct {
	Hash      []byte
	Signature []byte
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
func (s *Service) HandleTopologyCreationQuery(tcq *TopologyCreationQuery) (network.Message, onet.ClientError) {
	log.LLvl1(s.ServerIdentity(), "received a request for a new topology skipchain")

	res, err := s.CoSiPhase(tcq)
	if err != nil {
		return nil, err
	}

	a, _ := network.Marshal(tcq.StateTopology)

	// verify the response still
	verif := cosi.VerifySignature(network.Suite, tcq.Roster.Publics(), a, res.Signature)

	log.LLvl1("ANSWER",verif)

	verif = cosi.VerifySignature(network.Suite, tcq.Roster.Publics(), []byte(string("ola")), res.Signature)

	log.LLvl1("ANSWER",verif)

	log.LLvl1(s.ServerIdentity(), "successfuly created a topology skipchain")
	return &ServiceState{}, nil
}


// Service Phases
//______________________________________________________________________________________________________________________


// StartProtocol starts a CoSi protocol
func (s *Service) CoSiPhase(tcq *TopologyCreationQuery) (*SignatureResponse, onet.ClientError) {
	tree := tcq.Roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())
	tn := s.NewTreeNodeInstance(tree, tree.Root, cosi.Name)

	pi, err := cosi.NewProtocol(tn)
	if err != nil {
		return nil, onet.NewClientErrorCode(4100, "Couldn't make new protocol: "+err.Error())
	}

	s.RegisterProtocolInstance(pi)

	pcosi := pi.(*cosi.CoSi)

	message, err := network.Marshal(tcq.StateTopology)
	pcosi.SigningMessage(message)
	h, err := crypto.HashBytes(network.Suite.Hash(), message)
	if err != nil {
		return nil, onet.NewClientErrorCode(4101, "Couldn't hash message: "+err.Error())
	}

	response := make(chan []byte)
	pcosi.RegisterSignatureHook(func(sig []byte) {
		response <- sig
	})

	log.LLvl1("Starting up root protocol")
	go pi.Dispatch()
	go pi.Start()

	sig := <-response
	log.LLvlf1("%s: Signed a message", time.Now().Format("Mon Jan 2 15:04:05 -0700 MST 2006"))

	return &SignatureResponse{
		Hash:      h,
		Signature: sig,
	}, nil
}
