package main

import (
	"github.com/BurntSushi/toml"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/protocols"
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

		root := rooti.(*protocolsunlynx.KeySwitchingProtocol)
		suite := root.Suite()
		aggregateKey := root.Roster().Aggregate

		responses := make([]libunlynx.FilteredResponse, sim.NbrResponses)
		tabAttrs := make([]int64, sim.NbrAggrAttributes)
		for i := 0; i < sim.NbrAggrAttributes; i++ {
			tabAttrs[i] = int64(1)
		}
		tabGrps := make([]int64, sim.NbrGroupAttributes)
		for i := 0; i < sim.NbrGroupAttributes; i++ {
			tabGrps[i] = int64(1)
		}
		for i := 0; i < sim.NbrResponses; i++ {
			responses[i] = libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(aggregateKey, tabGrps), AggregatingAttributes: *libunlynx.EncryptIntVector(aggregateKey, tabAttrs)}
		}

		responsesct, _ := protocolsunlynx.FilteredResponseToCipherVector(responses)

		clientSecret := suite.Scalar().Pick(random.New())
		clientPublic := suite.Point().Mul(clientSecret, suite.Point().Base())

		root.ProtocolInstance().(*protocolsunlynx.KeySwitchingProtocol).TargetPublicKey = &clientPublic
		log.Lvl1("Number of respones to key switch ", len(responsesct))
		root.ProtocolInstance().(*protocolsunlynx.KeySwitchingProtocol).TargetOfSwitch = &responsesct
		root.ProtocolInstance().(*protocolsunlynx.KeySwitchingProtocol).Proofs = sim.Proofs

		round := libunlynx.StartTimer("_KeySwitching(SIMULATION)")

		root.Start()
		<-root.ProtocolInstance().(*protocolsunlynx.KeySwitchingProtocol).FeedbackChannel

		libunlynx.EndTimer(round)

	}

	return nil
}
