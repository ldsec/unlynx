package main

import (
	"github.com/BurntSushi/toml"
	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/JoaoAndreSa/MedCo/protocols"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"

	"gopkg.in/dedis/onet.v1/network"
)

var groupingAttrShuffle int // number of grouping attributes
var aggrAttrShuffle int     // number of aggregating attributes
var shuffle int             // number of clients (k)
var proofsShuffle bool
var precompute bool

func init() {
	onet.SimulationRegister("Shuffling", NewShufflingSimulation)
	onet.GlobalProtocolRegister("ShufflingSimul", NewShufflingSimul)

}

// ShufflingSimulation is the structure holding the state of the simulation.
type ShufflingSimulation struct {
	onet.SimulationBFTree

	NbrGroupAttributes int
	NbrAggrAttributes  int
	NbrResponses       int
	Proofs             bool
	PreCompute         bool
}

// NewShufflingSimulation is a constructor for the simulation.
func NewShufflingSimulation(config string) (onet.Simulation, error) {
	sim := &ShufflingSimulation{}
	_, err := toml.Decode(config, sim)

	if err != nil {
		return nil, err
	}
	return sim, nil
}

// Setup initializes a simulation.
func (sim *ShufflingSimulation) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
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
func (sim *ShufflingSimulation) Run(config *onet.SimulationConfig) error {
	groupingAttrShuffle = sim.NbrGroupAttributes
	aggrAttrShuffle = sim.NbrAggrAttributes
	shuffle = sim.NbrResponses
	proofsShuffle = sim.Proofs
	precompute = sim.PreCompute
	for round := 0; round < sim.Rounds; round++ {
		log.Lvl1("Starting round", round)
		rooti, err := config.Overlay.CreateProtocol("ShufflingSimul", config.Tree, onet.NilServiceID)

		if err != nil {
			return err
		}

		root := rooti.(*protocols.ShufflingProtocol)

		//complete protocol time measurement
		round := lib.StartTimer("_Shuffling(SIMULATION)")

		root.Start()

		<-root.ProtocolInstance().(*protocols.ShufflingProtocol).FeedbackChannel
		lib.EndTimer(round)
	}

	return nil
}

// NewShufflingSimul is a custom protocol constructor specific for simulation purposes.
func NewShufflingSimul(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {

	protocol, err := protocols.NewShufflingProtocol(tni)
	pap := protocol.(*protocols.ShufflingProtocol)
	pap.Proofs = proofsShuffle
	if precompute {
		pap.Precomputed = lib.CreatePrecomputedRandomize(suite.Point().Base(), tni.Roster().Aggregate, network.Suite.Cipher(tni.Private().Bytes()), int(groupingAttrShuffle) + int(aggrAttrShuffle), 10)
	}
	if tni.IsRoot() {
		aggregateKey := pap.Roster().Aggregate

		// Creates dummy data...
		clientResponses := make([]lib.ClientResponse, shuffle)
		tabGroup := make([]int64, groupingAttrShuffle)
		tabAttr := make([]int64, aggrAttrShuffle)

		for i := 0; i < groupingAttrShuffle; i++ {
			tabGroup[i] = int64(1)
		}
		for i := 0; i < aggrAttrShuffle; i++ {
			tabAttr[i] = int64(1)
		}

		encryptedGrp := *lib.EncryptIntVector(aggregateKey, tabGroup)
		encryptedAttr := *lib.EncryptIntVector(aggregateKey, tabAttr)
		clientResponse := lib.ClientResponse{GroupingAttributesClear: "", ProbaGroupingAttributesEnc: encryptedGrp, AggregatingAttributes: encryptedAttr}

		for i := 0; i < shuffle; i++ {
			clientResponses[i] = clientResponse
		}

		pap.TargetOfShuffle = &clientResponses
	}

	return pap, err
}
