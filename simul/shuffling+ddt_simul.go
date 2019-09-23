package main

import (
	"errors"
	"github.com/BurntSushi/toml"
	"github.com/ldsec/unlynx/lib"
	"github.com/ldsec/unlynx/lib/shuffle"
	"github.com/ldsec/unlynx/protocols"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

func init() {
	onet.SimulationRegister("ShufflingPlusDDT", NewShufflingPlusDDTSimulation)
}

// ShufflingPlusDDTSimulation is the structure holding the state of the simulation.
type ShufflingPlusDDTSimulation struct {
	onet.SimulationBFTree

	NbrResponses int
	Proofs       bool
	PreCompute   bool
}

// NewShufflingPlusDDTSimulation is a constructor for the simulation.
func NewShufflingPlusDDTSimulation(config string) (onet.Simulation, error) {
	sim := &ShufflingPlusDDTSimulation{}
	_, err := toml.Decode(config, sim)

	if err != nil {
		return nil, err
	}
	return sim, nil
}

// Setup initializes a simulation.
func (sim *ShufflingPlusDDTSimulation) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	sc := &onet.SimulationConfig{}
	sim.CreateRoster(sc, hosts, 2000)
	err := sim.CreateTree(sc)

	if err != nil {
		return nil, err
	}
	log.Lvl1("Setup done")
	return sc, nil
}

// Node registers a ShufflingSimul (with access to the ShufflingSimulation object) for every node
func (sim *ShufflingPlusDDTSimulation) Node(config *onet.SimulationConfig) error {
	if _, err := config.Server.ProtocolRegister("ShufflingPlusDDTSimul",
		func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
			return NewShufflingPlusDDTSimul(tni, sim)
		}); err != nil {
		return errors.New("Error while registering <ShufflingSimul>:" + err.Error())
	}

	return sim.SimulationBFTree.Node(config)
}

// Run starts the simulation.
func (sim *ShufflingPlusDDTSimulation) Run(config *onet.SimulationConfig) error {
	for round := 0; round < sim.Rounds; round++ {
		log.Lvl1("Starting round", round)
		rooti, err := config.Overlay.CreateProtocol("ShufflingPlusDDTSimul", config.Tree, onet.NilServiceID)

		if err != nil {
			return err
		}

		root := rooti.(*protocolsunlynx.ShufflingPlusDDTProtocol)

		//complete protocol time measurement
		round := libunlynx.StartTimer("_ShufflingPlusDDT(SIMULATION)")

		if err := root.Start(); err != nil {
			return err
		}
		<-root.ProtocolInstance().(*protocolsunlynx.ShufflingPlusDDTProtocol).FeedbackChannel

		libunlynx.EndTimer(round)
	}

	return nil
}

// NewShufflingPlusDDTSimul is a custom protocol constructor specific for simulation purposes.
func NewShufflingPlusDDTSimul(tni *onet.TreeNodeInstance, sim *ShufflingPlusDDTSimulation) (onet.ProtocolInstance, error) {
	protocol, err := protocolsunlynx.NewShufflingPlusDDTProtocol(tni)
	prot := protocol.(*protocolsunlynx.ShufflingPlusDDTProtocol)
	prot.Proofs = sim.Proofs

	if sim.PreCompute {
		precompute := libunlynx.StartTimer(tni.TreeNode().Name() + "_ShufflingPlusDDT(Precomputation)")
		b, err := tni.Private().MarshalBinary()
		if err != nil {
			panic("error unmarshiling scalar")
		}
		shufflingKey := tni.Roster().Aggregate.Clone()
		for i := 1; i < len(tni.Tree().List()); i++ {
			if tni.Tree().List()[i].Equal(tni.TreeNode()) {
				break
			}
			shufflingKey.Sub(shufflingKey, tni.Roster().List[tni.Tree().List()[i].RosterIndex].Public)
		}
		prot.Precomputed = libunlynxshuffle.CreatePrecomputedRandomize(libunlynx.SuiTe.Point().Base(), shufflingKey, libunlynx.SuiTe.XOF(b), 1, int(sim.NbrResponses))
		libunlynx.EndTimer(precompute)
	}
	if tni.IsRoot() {
		aggregateKey := prot.Roster().Aggregate

		// Creates dummy data...
		encryption := libunlynx.StartTimer(tni.TreeNode().Name() + "_ShufflingPlusDDT(DummyDataGenerationAndEncryption)")
		data := make([]int64, sim.NbrResponses)
		for i := 0; i < sim.NbrResponses; i++ {
			data[i] = int64(1)
		}
		encryptedData := *libunlynx.EncryptIntVector(aggregateKey, data)

		dataForProtocol := make([]libunlynx.CipherVector, sim.NbrResponses)
		for i, v := range encryptedData {
			dataForProtocol[i] = libunlynx.CipherVector{v}
		}
		prot.TargetData = &dataForProtocol
		libunlynx.EndTimer(encryption)
	}
	tempKey := libunlynx.SuiTe.Scalar().Pick(random.New())
	prot.SurveySecretKey = &tempKey

	return prot, err
}
