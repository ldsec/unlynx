package serviceSkipchain

import (
	"gopkg.in/dedis/onet.v1"
	"time"
	"gopkg.in/dedis/onet.v1/network"
	"gopkg.in/dedis/onet.v1/log"
	"github.com/dedis/cothority/cosi/protocol"
	"gopkg.in/dedis/onet.v1/crypto"
	"medblock/service/topology"
	"github.com/JoaoAndreSa/MedCo/protocols/skipchain"
	"gopkg.in/dedis/onet.v1/app"
	"os"
	"github.com/dedis/cothority/skipchain"
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
type ServiceState struct {
	Block	*skipchain.SkipBlock
}

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

	log.LLvl1("Check if each node agrees with the new topology skipblock")

	roster, err := s.AgreementPhase(tcq)
	if err != nil {
		return nil, err
	}
	tcq.Roster = *roster

	if len(tcq.Roster.List) > 0 {
		res, err := s.CoSiPhase(tcq)
		if err != nil {
			return nil, err
		}

		dataSigned, _ := network.Marshal(tcq.StateTopology)

		// verify the response still
		verif := cosi.VerifySignature(network.Suite, tcq.Roster.Publics(), dataSigned, res.Signature)

		if verif != nil {
			log.LLvl1("Invalid signature")
			return &ServiceState{}, onet.NewClientErrorCode(4100, "Invalid signature")
		}

		log.LLvl1("Valid signature")

		// Add data to state topology block to be sent to the skipchain cothority
		tcq.StateTopology.SignKeys = tcq.Roster.Publics()
		tcq.StateTopology.Signature = res.Signature

		//log.LLvl1("ANSWER:",verif)

		//verif = cosi.VerifySignature(network.Suite, tcq.Roster.Publics(), []byte(string("ola")), res.Signature)

		//log.LLvl1("ANSWER:",verif)

		// Send a request to the skipchain medblock service
		log.LLvl1("Sending the block to the skipchain cothority")
		client := topology.NewTopologyClient()
		sb, cerr := client.CreateNewTopology(&tcq.Roster,tcq.StateTopology)
		if cerr != nil {
			log.LLvl1("Error adding block")
			return &ServiceState{}, onet.NewClientErrorCode(4100, "Could not add block to the skipchain cothority")
		}

		log.LLvl1(s.ServerIdentity(), "successfuly created a topology skipchain")
		return &ServiceState{Block: sb}, nil
	} else {
		return &ServiceState{Block: nil}, onet.NewClientErrorCode(4100, "No node agreed to add this block")
	}
}


// Service Phases
//______________________________________________________________________________________________________________________


func (s *Service) AgreementPhase(tcq *TopologyCreationQuery) (*onet.Roster, onet.ClientError){
	tree := tcq.Roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())
	tn := s.NewTreeNodeInstance(tree, tree.Root, protocols.VerifyBlockProtocolName)

	pi, err := protocols.NewVerifyBlockProtocol(tn)
	if err != nil {
		return nil, onet.NewClientErrorCode(4100, "Couldn't make new protocol: "+err.Error())
	}

	s.RegisterProtocolInstance(pi)

	pverif := pi.(*protocols.VerifyBlockProtocol)

	b, err := network.Marshal(tcq.StateTopology)
	if err != nil {
		log.Fatal("While marshalling")
		return nil, onet.NewClientErrorCode(4100, "Couldn't marshal the block: "+err.Error())
	}

	pverif.TargetBlock = b

	log.LLvl1("Starting up root protocol")
	go pi.Start()

	f := <- pverif.FeedbackChannel

	roster := onet.Roster{List: f.List}
	return &roster, nil
}


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

// Get the skipchain cothority roster
func getRoster(filepath string) (*onet.Roster, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	el, err := app.ReadGroupToml(f)

	if err!= nil{
		return nil, err
	}

	return el, nil
}
