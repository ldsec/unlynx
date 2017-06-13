package main

import (
	"github.com/BurntSushi/toml"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/protocols"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
)

func init() {
	onet.SimulationRegister("KeySwitching", NewKeySwitchingSimulation)

}

// KeySwitchingSimulation holds the state of a simulation.
type KeySwitchingSimulation struct {
	onet.SimulationBFTree

	NbrResponses       int
	NbrAggrAttributes  int
	NbrGroupAttributes int
	Proofs             bool
}

// NewKeySwitchingSimulation constructs a key switching simulation.
func NewKeySwitchingSimulation(config string) (onet.Simulation, error) {
	sim := &KeySwitchingSimulation{}
	_, err := toml.Decode(config, sim)

	if err != nil {
		return nil, err
	}
	return sim, nil
}

// Setup initializes the simulation.
func (sim *KeySwitchingSimulation) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
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
func (sim *KeySwitchingSimulation) Run(config *onet.SimulationConfig) error {
	for round := 0; round < sim.Rounds; round++ {
		log.Lvl1("Starting round", round)
		rooti, err := config.Overlay.CreateProtocol("KeySwitching", config.Tree, onet.NilServiceID)
		if err != nil {
			return err
		}

		root := rooti.(*protocols.KeySwitchingProtocol)
		suite := root.Suite()
		aggregateKey := root.Roster().Aggregate

		responses := make([]lib.FilteredResponse, sim.NbrResponses)
		tabAttrs := make([]int64, sim.NbrAggrAttributes)
		for i := 0; i < sim.NbrAggrAttributes; i++ {
			tabAttrs[i] = int64(1)
		}
		tabGrps := make([]int64, sim.NbrGroupAttributes)
		for i := 0; i < sim.NbrGroupAttributes; i++ {
			tabGrps[i] = int64(1)
		}
		for i := 0; i < sim.NbrResponses; i++ {
			responses[i] = lib.FilteredResponse{GroupByEnc: *lib.EncryptIntVector(aggregateKey, tabGrps), AggregatingAttributes: *lib.EncryptIntVector(aggregateKey, tabAttrs)}
		}

		clientSecret := suite.Scalar().Pick(random.Stream)
		clientPublic := suite.Point().Mul(suite.Point().Base(), clientSecret)

		root.ProtocolInstance().(*protocols.KeySwitchingProtocol).TargetPublicKey = &clientPublic
		log.Lvl1("Number of respones to key switch ", len(responses))
		root.ProtocolInstance().(*protocols.KeySwitchingProtocol).TargetOfSwitch = &responses
		root.ProtocolInstance().(*protocols.KeySwitchingProtocol).Proofs = sim.Proofs

		round := lib.StartTimer("_KeySwitching(SIMULATION)")

		root.Start()
		<-root.ProtocolInstance().(*protocols.KeySwitchingProtocol).FeedbackChannel

		lib.EndTimer(round)

	}

	return nil
}
