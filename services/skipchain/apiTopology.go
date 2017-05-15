package serviceSkipchain

import (
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
	"gopkg.in/dedis/crypto.v0/config"
	"gopkg.in/dedis/onet.v1/log"
	"medblock/service/topology"
)

// API represents a client with the server to which he is connected and its public/private key pair.
type API struct {
	*onet.Client
	clientID   string
	entryPoint *network.ServerIdentity
	public     abstract.Point
	private    abstract.Scalar
}

// NewTopologyClient constructor of a client.
func NewTopologyClient(entryPoint *network.ServerIdentity, clientID string) *API {
	keys := config.NewKeyPair(network.Suite)

	newClient := &API{
		Client:     onet.NewClient(ServiceName),
		clientID:   clientID,
		entryPoint: entryPoint,
		public:     keys.Public,
		private:    keys.Secret,
	}
	return newClient
}


// Create the Topology Skipchain (to be performed by an admin or data provider)
//______________________________________________________________________________________________________________________

// SendTopologyCreationQuery asks the server to validate the new block and then request the skipchain cothority to use
// as the genesis block for a new topology skipchain
func (c *API) SendTopologyCreationQuery(entities *onet.Roster, st *topology.StateTopology) (error) {
	log.LLvl1("Client [",c.clientID, "] requests the creation of a new topology skipchain")

	tcq := TopologyCreationQuery{
		StateTopology: st,
		IntraMessage: false,
		Roster: *entities,
	}

	resp := ServiceState{}
	err := c.SendProtobuf(c.entryPoint, &tcq, &resp)
	if err != nil {
		return err
	}

	log.LLvl1("Client [",c.clientID,"] successfully created a new topology skipchain")

	log.LLvl1("Genesis block:",*topology.UnmarshalData(resp.Block))
	return nil
}

// Update the Topology Skipchain (to be performed by an admin or data provider)
//______________________________________________________________________________________________________________________

// SendTopologyUpdateQuery asks the server to validate the new block and then request the skipchain cothority to add it
// to the topology skipchain
func (c *API) SendTopologyUpdateQuery() () {

}

// Get Last Block of the Topology Skipchain (to be performed by the querier prior to starting a medco protocol)
//______________________________________________________________________________________________________________________

// SendTopologyGetQuery asks the server to to communicate with the skipchain cothority and retrieve the last block from
// the topology skipchain
func (c *API) SendTopologyGetQuery() () {

}

// Get the blocks in a time interval (for someone who is auditing the system)
//______________________________________________________________________________________________________________________

// SendTopologySearchQuery asks the server to communicate with the skipchain cothority and requests all the blocks that
// exist in a certain time interval.
func (c *API) SendTopologySearchQuery() () {

}

