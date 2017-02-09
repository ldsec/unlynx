package main

import (
	"github.com/BurntSushi/toml"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/crypto.v0/random"
	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/JoaoAndreSa/MedCo/protocols"
)

func init() {
	onet.SimulationRegister("AddRmServer", NewAddRmSimulation)

}

// AddRmSimulation holds the state of a simulation.
type AddRmSimulation struct {
	onet.SimulationBFTree

	NbrResponses        int
	NbrGroupsAttributes int
	NbrAttributesAggr   int
	ProofsAddRm         bool
	Add                 bool
}

// NewAddRmSimulation constructs an adding/removing protocol simulation.
func NewAddRmSimulation(config string) (onet.Simulation, error) {
	sim := &AddRmSimulation{}
	_, err := toml.Decode(config, sim)

	if err != nil {
		return nil, err
	}
	return sim, nil
}

// Setup initializes the simulation.
func (sim *AddRmSimulation) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	sc := &onet.SimulationConfig{}
	sim.CreateRoster(sc, hosts, 2000)
	err := sim.CreateTree(sc)

	if err != nil {
		return nil, err
	}

	log.Lvl1("Setup done")

	return sc, nil
}

// Run starts the simulation.
func (sim *AddRmSimulation) Run(config *onet.SimulationConfig) error {
	log.SetDebugVisible(1)
	for round := 0; round < sim.Rounds; round++ {
		log.Lvl1("Starting round", round)

		rooti, err := config.Overlay.CreateProtocol("AddRmServer",config.Tree,onet.NilServiceID)

		if err != nil {
			return err
		}

		root := rooti.(*protocols.AddRmServerProtocol)

		secKey := network.Suite.Scalar().Pick(random.Stream)
		newSecKey := network.Suite.Scalar().Pick(random.Stream)
		pubKey := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)

		tab := make([]int64, sim.NbrAttributesAggr)
		for i := 0; i < len(tab); i++ {
			tab[i] = int64(1)
		}
		tabGr := make([]int64, sim.NbrGroupsAttributes)
		for i := 0; i < len(tabGr); i++ {
			tabGr[i] = int64(1)
		}

		// aggregation
		testCipherVect1 := *lib.EncryptIntVector(pubKey, tab)
		groupCipherVect := *lib.EncryptIntVector(pubKey, tabGr)
		cr := lib.ClientResponse{ProbaGroupingAttributesEnc: groupCipherVect, AggregatingAttributes: testCipherVect1}
		detResponses := make([]lib.ClientResponse, 0)
		for i := 0; i < sim.NbrResponses; i++ {
			detResponses = append(detResponses, cr)
		}

		log.LLvl1("starting protocol with ", len(detResponses), " responses")

		root.ProtocolInstance().(*protocols.AddRmServerProtocol).TargetOfTransformation = detResponses
		root.ProtocolInstance().(*protocols.AddRmServerProtocol).Proofs = sim.ProofsAddRm
		root.ProtocolInstance().(*protocols.AddRmServerProtocol).Add = sim.Add
		root.ProtocolInstance().(*protocols.AddRmServerProtocol).KeyToRm = newSecKey

		round := lib.StartTimer("_LocalAddRm(Simulation")

		root.Start()
		results := <-root.ProtocolInstance().(*protocols.AddRmServerProtocol).FeedbackChannel
		log.LLvl1("Number of aggregated lines: ", len(results))

		lib.EndTimer(round)

	}

	return nil
}
