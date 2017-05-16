package serviceSkipchain

import (
	"github.com/JoaoAndreSa/MedCo/protocols/skipchain"
	"github.com/dedis/cothority/cosi/protocol"
	"github.com/dedis/cothority/skipchain"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/app"
	"gopkg.in/dedis/onet.v1/crypto"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"medblock/service/topology"
	"os"
	"time"
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

// TopologyUpdateQuery asking all nodes in Roster to participate and sign the new block before
// sending it to the skipchain cothority.
type TopologyUpdateQuery struct {
	//Topology to be stored in the genesis block
	*topology.StateTopology
	//If the message comes from a client or from a server
	IntraMessage bool
	//Conodes which have to participate in the creation of the topology skipchain
	Roster onet.Roster
	//Previous skipblock (or any other skipblock)
	PrevSB *skipchain.SkipBlock
}

// ServiceState is the response to the different api requests
type ServiceState struct {
	Block *skipchain.SkipBlock
}

// SignatureResponse is what the Cosi protocol will reply to clients.
type SignatureResponse struct {
	Hash      []byte
	Signature []byte
}

//SERVICE

func init() {
	onet.RegisterNewService(ServiceName, NewService)

	network.RegisterMessage(&TopologyCreationQuery{})
	network.RegisterMessage(&TopologyUpdateQuery{})

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
	if cerr := newInstance.RegisterHandler(newInstance.HandleTopologyUpdateQuery); cerr != nil {
		log.Fatal("Wrong Handler.", cerr)
	}

	return newInstance
}

// Query Handlers
//______________________________________________________________________________________________________________________

// HandleTopologyCreationQuery handles the reception of a topology creation query.
func (s *Service) HandleTopologyCreationQuery(tcq *TopologyCreationQuery) (network.Message, onet.ClientError) {
	log.LLvl1(s.ServerIdentity(), "received a request for a new topology skipchain")

	st, cerr := s.StartService(tcq.Roster, tcq.StateTopology)
	if cerr != nil {
		return nil, cerr
	}

	// Send a request to the skipchain medblock service
	client := topology.NewTopologyClient()
	sb, cerr := client.CreateNewTopology(&tcq.Roster, st)
	if cerr != nil {
		log.LLvl1("Error adding block")
		return &ServiceState{}, onet.NewClientErrorCode(4100, "Could not add block to the skipchain cothority")
	}

	log.LLvl1(s.ServerIdentity(), "successfuly created a topology skipchain")
	return &ServiceState{Block: sb}, nil
}

// HandleTopologyUpdateQuery handles the reception of a topology update query.
func (s *Service) HandleTopologyUpdateQuery(tuq *TopologyUpdateQuery) (network.Message, onet.ClientError) {
	log.LLvl1(s.ServerIdentity(), "received a request for an update on the topology skipchain")

	st, cerr := s.StartService(tuq.Roster, tuq.StateTopology)
	if cerr != nil {
		return nil, cerr
	}

	// Send a request to the skipchain medblock service
	client := topology.NewTopologyClient()
	sb, cerr := client.UpdateTopology(&tuq.Roster, tuq.PrevSB, st)
	if cerr != nil {
		log.LLvl1("Error adding block")
		return &ServiceState{}, onet.NewClientErrorCode(4100, "Could not add block to the skipchain cothority")
	}

	log.LLvl1(s.ServerIdentity(), "successfuly added a new topology skipblock")
	return &ServiceState{Block: sb}, nil
}




// HandleTopologyUpdateQuery handles the reception of a topology update query.

// Service Phases
//______________________________________________________________________________________________________________________

// StartService starts a create or update service to create a new skipchain or add a new block to that skipchain
func (s *Service) StartService(roster onet.Roster, st *topology.StateTopology) (*topology.StateTopology, onet.ClientError) {

	log.LLvl1("Check if each node agrees with the new topology skipblock")

	rosterAccepted, err := s.AgreementPhase(roster, st)
	if err != nil {
		return nil, err
	}
	roster = *rosterAccepted

	if len(roster.List) > 0 {
		res, err := s.CoSiPhase(roster, st)
		if err != nil {
			return nil, err
		}

		dataSigned, _ := network.Marshal(&st.Data)

		// verify the response still
		verif := cosi.VerifySignature(network.Suite, roster.Publics(), dataSigned, res.Signature)

		if verif != nil {
			log.LLvl1("Invalid CoSi signature")
			return nil, onet.NewClientErrorCode(4100, "Invalid CoSi signature")
		}

		log.LLvl1("Valid CoSi signature")

		// Add data to state topology block to be sent to the skipchain cothority
		st.SignKeys = roster.Publics()
		st.Signature = res.Signature

		//log.LLvl1("ANSWER:",verif)

		//verif = cosi.VerifySignature(network.Suite, tcq.Roster.Publics(), []byte(string("ola")), res.Signature)

		//log.LLvl1("ANSWER:",verif)

		return st, nil
	}

	return nil, onet.NewClientErrorCode(4100, "No node agreed to add this block")
}

// AgreementPhase starts a VerifyBlock protocol
func (s *Service) AgreementPhase(roster onet.Roster, st *topology.StateTopology) (*onet.Roster, onet.ClientError) {
	tree := roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())
	tn := s.NewTreeNodeInstance(tree, tree.Root, protocols.VerifyBlockProtocolName)

	pi, err := protocols.NewVerifyBlockProtocol(tn)
	if err != nil {
		return nil, onet.NewClientErrorCode(4100, "Couldn't make new protocol: "+err.Error())
	}

	s.RegisterProtocolInstance(pi)

	pverif := pi.(*protocols.VerifyBlockProtocol)

	b, err := network.Marshal(st)
	if err != nil {
		log.Fatal("While marshalling")
		return nil, onet.NewClientErrorCode(4100, "Couldn't marshal the block: "+err.Error())
	}

	pverif.TargetBlock = b

	log.LLvl1("Starting up root protocol")
	go pi.Start()

	f := <-pverif.FeedbackChannel

	rosterAccept := onet.Roster{List: f.List}
	return &rosterAccept, nil
}

// CoSiPhase starts a CoSi protocol
func (s *Service) CoSiPhase(roster onet.Roster, st *topology.StateTopology) (*SignatureResponse, onet.ClientError) {
	tree := roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())
	tn := s.NewTreeNodeInstance(tree, tree.Root, cosi.Name)

	pi, err := cosi.NewProtocol(tn)
	if err != nil {
		return nil, onet.NewClientErrorCode(4100, "Couldn't make new protocol: "+err.Error())
	}

	s.RegisterProtocolInstance(pi)

	pcosi := pi.(*cosi.CoSi)

	message, err := network.Marshal(&st.Data)
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

	if err != nil {
		return nil, err
	}

	return el, nil
}
