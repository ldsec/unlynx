package main

import (
	"github.com/BurntSushi/toml"
	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/JoaoAndreSa/MedCo/protocols"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

var suite = network.Suite
var grpattr = lib.DeterministCipherText{Point: suite.Point().Base()}
var clientPrivate = suite.Scalar().One() //one -> to have the same for each node
var clientPublic = suite.Point().Mul(suite.Point().Base(), clientPrivate)

var nbrGroups int
var nbrGroupAttributes int
var nbrAggrAttributes int
var attribMap map[lib.GroupingKey]lib.ClientResponse

func createDataSet(numberGroups, numberAttributes, numberGroupAttr int) map[lib.GroupingKey]lib.ClientResponse {
	testCVMap := make(map[lib.GroupingKey]lib.ClientResponse)

	tabGrp := make([]int64, numberGroupAttr)
	for i := 0; i < numberGroupAttr; i++ {
		tabGrp[i] = int64(1)
	}

	dummyGroups := *lib.EncryptIntVector(clientPublic, tabGrp)
	for i := 0; i < numberGroups; i++ {
		newGrpattr := grpattr
		(lib.DeterministCipherText(newGrpattr).Point).Add(lib.DeterministCipherText(newGrpattr).Point,
			lib.DeterministCipherText(newGrpattr).Point)
		groupAttributes := lib.DeterministCipherVector{grpattr, newGrpattr}

		grpattr = newGrpattr

		tab := make([]int64, numberAttributes)
		for i := 0; i < numberAttributes; i++ {
			tab[i] = int64(1)
		}

		cipherVect := *lib.EncryptIntVector(clientPublic, tab)

		testCVMap[groupAttributes.Key()] = lib.ClientResponse{GroupingAttributesClear: "", ProbaGroupingAttributesEnc: dummyGroups, AggregatingAttributes: cipherVect}
	}
	return testCVMap
}

func init() {
	onet.SimulationRegister("CollectiveAggregation", NewCollectiveAggregationSimulation)
	onet.GlobalProtocolRegister("CollectiveAggregationSimul", NewAggregationProtocolSimul)
}

// CollectiveAggregationSimulation holds the state of a simulation.
type CollectiveAggregationSimulation struct {
	onet.SimulationBFTree

	NbrGroups          int
	NbrGroupAttributes int
	NbrAggrAttributes  int
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
	sim.CreateRoster(sc, hosts, 20)
	err := sim.CreateTree(sc)

	if err != nil {
		return nil, err
	}

	log.Lvl1("Setup done")

	return sc, nil

}

// Run starts the simulation of the protocol and measures its runtime.
func (sim *CollectiveAggregationSimulation) Run(config *onet.SimulationConfig) error {
	nbrGroups = sim.NbrGroups
	nbrGroupAttributes = sim.NbrGroupAttributes
	nbrAggrAttributes = sim.NbrAggrAttributes

	attribMap = createDataSet(nbrGroups, nbrAggrAttributes, nbrGroupAttributes)

	for round := 0; round < sim.Rounds; round++ {
		log.Lvl1("Starting round", round)
		rooti, err := config.Overlay.CreateProtocol("CollectiveAggregationSimul", config.Tree, onet.NilServiceID)
		if err != nil {
			log.LLvl1("error Run")
			return err
		}

		root := rooti.(*protocols.CollectiveAggregationProtocol)

		//time measurement
		round := lib.StartTimer("CollectiveAggregation(SIMULATION)")

		log.LLvl1("Start protocol")
		root.Start()
		<-root.ProtocolInstance().(*protocols.CollectiveAggregationProtocol).FeedbackChannel

		lib.EndTimer(round)
	}

	return nil
}

// NewAggregationProtocolSimul is a simulation specific protocol instance constructor that injects test data.
func NewAggregationProtocolSimul(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	protocol, err := protocols.NewCollectiveAggregationProtocol(tni)
	pap := protocol.(*protocols.CollectiveAggregationProtocol)

	pap.GroupedData = &attribMap
	pap.Proofs = true
	_ = pap
	_ = attribMap
	return pap, err
}
