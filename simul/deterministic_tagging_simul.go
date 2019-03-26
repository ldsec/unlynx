package main

import (
	"github.com/BurntSushi/toml"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/protocols"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul/monitor"
)

func init() {
	onet.SimulationRegister("DeterministicTagging", NewDeterministicTaggingSimulation)
}

// DeterministicTaggingSimulation is the structure holding the state of the simulation.
type DeterministicTaggingSimulation struct {
	onet.SimulationBFTree

	NbrResponses       int
	NbrGroupAttributes int
	NbrAggrAttributes  int
	Proofs             bool
}

// NewDeterministicTaggingSimulation is a constructor for the simulation.
func NewDeterministicTaggingSimulation(config string) (onet.Simulation, error) {
	sim := &DeterministicTaggingSimulation{}
	_, err := toml.Decode(config, sim)

	if err != nil {
		return nil, err
	}
	return sim, nil
}

// Setup initializes a simulation.
func (sim *DeterministicTaggingSimulation) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	sc := &onet.SimulationConfig{}
	sim.CreateRoster(sc, hosts, 2000)
	err := sim.CreateTree(sc)

	if err != nil {
		return nil, err
	}

	log.Lvl1("Setup done")

	return sc, nil
}

// Node registers a DeterministicTaggingSimul (with access to the DeterministicTaggingSimulation object) for every node
func (sim *DeterministicTaggingSimulation) Node(config *onet.SimulationConfig) error {
	config.Server.ProtocolRegister("DeterministicTaggingSimul",
		func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
			return NewDeterministicTaggingSimul(tni, sim)
		})

	return sim.SimulationBFTree.Node(config)
}

// Run starts the simulation.
func (sim *DeterministicTaggingSimulation) Run(config *onet.SimulationConfig) error {
	for round := 0; round < sim.Rounds; round++ {
		log.Lvl1("Starting round", round)
		rooti, err := config.Overlay.CreateProtocol("DeterministicTaggingSimul", config.Tree, onet.NilServiceID)

		if err != nil {
			return err
		}

		root := rooti.(*protocolsunlynx.DeterministicTaggingProtocol)

		//complete protocol time measurement
		round := monitor.NewTimeMeasure("DetTagging(SIMULATION)")
		root.Start()

		<-root.ProtocolInstance().(*protocolsunlynx.DeterministicTaggingProtocol).FeedbackChannel

		round.Record()
	}

	return nil
}

// NewDeterministicTaggingSimul is a custom protocol constructor specific for simulation purposes.
func NewDeterministicTaggingSimul(tni *onet.TreeNodeInstance, sim *DeterministicTaggingSimulation) (onet.ProtocolInstance, error) {
	protocol, err := protocolsunlynx.NewDeterministicTaggingProtocol(tni)
	pap := protocol.(*protocolsunlynx.DeterministicTaggingProtocol)
	pap.Proofs = sim.Proofs

	if tni.IsRoot() {
		aggregateKey := pap.Roster().Aggregate

		// Creates dummy data...
		processResponses := make([]libunlynx.ProcessResponse, sim.NbrResponses)
		tabGroup := make([]int64, sim.NbrGroupAttributes)
		tabAttr := make([]int64, sim.NbrAggrAttributes)

		for i := 0; i < sim.NbrGroupAttributes; i++ {
			tabGroup[i] = int64(1)
		}
		for i := 0; i < sim.NbrAggrAttributes; i++ {
			tabAttr[i] = int64(1)
		}

		encryptedGrp := *libunlynx.EncryptIntVector(aggregateKey, tabGroup)
		encryptedAttr := *libunlynx.EncryptIntVector(aggregateKey, tabAttr)
		processResponse := libunlynx.ProcessResponse{GroupByEnc: encryptedGrp, AggregatingAttributes: encryptedAttr}

		for i := 0; i < sim.NbrResponses; i++ {
			processResponses[i] = processResponse
		}
		ct := protocolsunlynx.ProcessResponseToCipherVector(processResponses)
		pap.TargetOfSwitch = &ct
	}
	tempKey := libunlynx.SuiTe.Scalar().Pick(random.New())
	pap.SurveySecretKey = &tempKey

	return pap, err
}
