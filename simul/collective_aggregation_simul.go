package main

import (
	"github.com/BurntSushi/toml"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/protocols"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"

	"time"
)

//var suite = network.Suite
//var grpattr = lib.DeterministCipherText{Point: suite.Point().Base()}
//var clientPrivate = suite.Scalar().One() //one -> to have the same for each node
//var clientPublic = suite.Point().Mul(suite.Point().Base(), clientPrivate)
var sum time.Duration

func createDataSet(numberGroups, numberAttributes, numberGroupAttr int) map[lib.GroupingKey]lib.FilteredResponse {
	var secContrib = network.Suite.Scalar().One()
	var clientPrivate = network.Suite.Scalar().One() //one -> to have the same for each node
	var clientPublic = network.Suite.Point().Mul(network.Suite.Point().Base(), clientPrivate)

	testCVMap := make(map[lib.GroupingKey]lib.FilteredResponse)

	tabGrp := make([]int64, numberGroupAttr)
	for i := 0; i < numberGroupAttr; i++ {
		tabGrp[i] = int64(1)
	}

	dummyGroups := *lib.EncryptIntVector(clientPublic, tabGrp)
	for i := 0; i < numberGroups; i++ {
		tab := make([]int64, numberAttributes)
		for i := 0; i < numberAttributes; i++ {
			tab[i] = int64(1)
		}

		cipherVect := *lib.EncryptIntVector(clientPublic, tab)

		testCVMap[lib.CipherVectorToDeterministicTag(*lib.EncryptIntVector(clientPublic, []int64{int64(i)}), clientPrivate, secContrib, clientPublic, false)] = lib.FilteredResponse{GroupByEnc: dummyGroups, AggregatingAttributes: cipherVect}
	}
	return testCVMap
}

func init() {
	onet.SimulationRegister("CollectiveAggregation", NewCollectiveAggregationSimulation)
}

// CollectiveAggregationSimulation holds the state of a simulation.
type CollectiveAggregationSimulation struct {
	onet.SimulationBFTree

	NbrGroups          int
	NbrGroupAttributes int
	NbrAggrAttributes  int
	Proofs             bool
}

// NewCollectiveAggregationSimulation is the simulation instance constructor.
func NewCollectiveAggregationSimulation(config string) (onet.Simulation, error) {
	sim := &CollectiveAggregationSimulation{}
	_, err := toml.Decode(config, sim)
	if err != nil {
		return nil, err
	}

	return sim, nil
}

// Setup initializes the simulation.
func (sim *CollectiveAggregationSimulation) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	sc := &onet.SimulationConfig{}
	sim.CreateRoster(sc, hosts, 2000)
	err := sim.CreateTree(sc)

	if err != nil {
		return nil, err
	}

	log.Lvl1("Setup done")

	return sc, nil
}

// Node registers a CollectiveAggregationSimul (with access to the CollectiveAggregationSimulation object) for every node
func (sim *CollectiveAggregationSimulation) Node(config *onet.SimulationConfig) error {
	config.Server.ProtocolRegister("CollectiveAggregationSimul",
		func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
			return NewAggregationProtocolSimul(tni, sim)
		})

	return sim.SimulationBFTree.Node(config)
}

// Run starts the simulation of the protocol and measures its runtime.
func (sim *CollectiveAggregationSimulation) Run(config *onet.SimulationConfig) error {

	for round := 0; round < sim.Rounds; round++ {
		sum = 0
		log.Lvl1("Starting round", round)
		rooti, err := config.Overlay.CreateProtocol("CollectiveAggregationSimul", config.Tree, onet.NilServiceID)
		if err != nil {
			log.Lvl1("error Run")
			return err
		}

		root := rooti.(*protocols.CollectiveAggregationProtocol)

		//time measurement
		round := lib.StartTimer("CollectiveAggregation(SIMULATION)")
		log.Lvl1("Start protocol")
		root.Start()
		log.Lvl1(<-root.ProtocolInstance().(*protocols.CollectiveAggregationProtocol).FeedbackChannel)

		lib.EndTimer(round)

	}
	return nil

}

// NewAggregationProtocolSimul is a simulation specific protocol instance constructor that injects test data.
func NewAggregationProtocolSimul(tni *onet.TreeNodeInstance, sim *CollectiveAggregationSimulation) (onet.ProtocolInstance, error) {

	protocol, err := protocols.NewCollectiveAggregationProtocol(tni)
	pap := protocol.(*protocols.CollectiveAggregationProtocol)

	data := createDataSet(sim.NbrGroups, sim.NbrAggrAttributes, sim.NbrGroupAttributes)
	pap.GroupedData = &data
	pap.Proofs = sim.Proofs
	return pap, err
}
