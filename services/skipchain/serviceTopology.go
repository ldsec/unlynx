package serviceSkipchain

import (
	"gopkg.in/dedis/onet.v1"
	"time"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1/crypto"
	"gopkg.in/dedis/onet.v1/network"
	"gopkg.in/dedis/onet.v1/log"
	"github.com/JoaoAndreSa/MedCo/services"
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

	if recq.IntraMessage==false{
		recq.IntraMessage = true

		err := services.SendISMOthers(s.ServiceProcessor, &recq.Roster, recq)
		if err != nil {
			log.Error("broadcasting error ", err)
		}

		time.Sleep(5*time.Second)

	}

	log.LLvl1(s.ServerIdentity(), "successfuly created a topology skipchain")
	return &ServiceState{Error: nil}, nil
}
