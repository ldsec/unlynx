package main

import (
	"github.com/BurntSushi/toml"
	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/shuffle"
	"github.com/lca1/unlynx/protocols"
)

func init() {
	onet.SimulationRegister("Shuffling", NewShufflingSimulation)
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

// Node registers a ShufflingSimul (with access to the ShufflingSimulation object) for every node
func (sim *ShufflingSimulation) Node(config *onet.SimulationConfig) error {
	config.Server.ProtocolRegister("ShufflingSimul",
		func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
			return NewShufflingSimul(tni, sim)
		})

	return sim.SimulationBFTree.Node(config)
}

// Run starts the simulation.
func (sim *ShufflingSimulation) Run(config *onet.SimulationConfig) error {
	for round := 0; round < sim.Rounds; round++ {
		log.Lvl1("Starting round", round)
		rooti, err := config.Overlay.CreateProtocol("ShufflingSimul", config.Tree, onet.NilServiceID)

		if err != nil {
			return err
		}

		root := rooti.(*protocolsunlynx.ShufflingProtocol)

		//complete protocol time measurement
		round := libunlynx.StartTimer("_Shuffling(SIMULATION)")

		root.Start()

		<-root.ProtocolInstance().(*protocolsunlynx.ShufflingProtocol).FeedbackChannel
		libunlynx.EndTimer(round)
	}

	return nil
}

// NewShufflingSimul is a custom protocol constructor specific for simulation purposes.
func NewShufflingSimul(tni *onet.TreeNodeInstance, sim *ShufflingSimulation) (onet.ProtocolInstance, error) {
	protocol, err := protocolsunlynx.NewShufflingProtocol(tni)
	pap := protocol.(*protocolsunlynx.ShufflingProtocol)
	pap.Proofs = sim.Proofs
	pap.ProofFunc = func(shuffleTarget, shuffledData []libunlynx.CipherVector, collectiveKey kyber.Point, beta [][]kyber.Scalar, pi []int) *libunlynxshuffle.PublishedShufflingProof {
		proof := libunlynxshuffle.ShuffleProofCreation(shuffleTarget, shuffledData, libunlynx.SuiTe.Point().Base(), collectiveKey, beta, pi)
		return &proof
	}

	if sim.PreCompute {
		b, err := tni.Private().MarshalBinary()
		if err != nil {
			panic("error unmarshiling scalar")
		}
		pap.Precomputed = libunlynx.CreatePrecomputedRandomize(libunlynx.SuiTe.Point().Base(), tni.Roster().Aggregate, libunlynx.SuiTe.XOF(b), int(sim.NbrGroupAttributes)+int(sim.NbrAggrAttributes), 10)
	}
	if tni.IsRoot() {
		aggregateKey := pap.Roster().Aggregate

		// Creates dummy data...
		clientResponses := make([]libunlynx.ProcessResponse, sim.NbrResponses)
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
		clientResponse := libunlynx.ProcessResponse{GroupByEnc: encryptedGrp, AggregatingAttributes: encryptedAttr}

		for i := 0; i < sim.NbrResponses; i++ {
			clientResponses[i] = clientResponse
		}

		targetToShuffle, _ := protocolsunlynx.ProcessResponseToMatrixCipherText(clientResponses)
		pap.ShuffleTarget = &targetToShuffle
	}

	return pap, err
}
