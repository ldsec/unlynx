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
	onet.SimulationRegister("AddRmServer", NewAddRmSimulation)

}

// AddRmSimulation holds the state of a simulation.
type AddRmSimulation struct {
	onet.SimulationBFTree

	NbrResponses int //to make sense all the different attributes are encrypted
	Proofs       bool
	Add          bool
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
	for round := 0; round < sim.Rounds; round++ {
		log.Lvl1("Starting round", round)

		rooti, err := config.Overlay.CreateProtocol("AddRmServer", config.Tree, onet.NilServiceID)

		if err != nil {
			return err
		}

		root := rooti.(*protocolsunlynx.AddRmServerProtocol)

		secKey := libunlynx.SuiTe.Scalar().Pick(random.New())
		newSecKey := libunlynx.SuiTe.Scalar().Pick(random.New())
		pubKey := libunlynx.SuiTe.Point().Mul(secKey, libunlynx.SuiTe.Point().Base())

		ct := make(libunlynx.CipherVector, sim.NbrResponses)
		for i := range ct {
			ct[i] = *libunlynx.EncryptInt(pubKey, 1)
		}

		log.Lvl1("starting protocol with ", len(ct), " responses")

		root.ProtocolInstance().(*protocolsunlynx.AddRmServerProtocol).TargetOfTransformation = ct
		root.ProtocolInstance().(*protocolsunlynx.AddRmServerProtocol).Proofs = sim.Proofs
		root.ProtocolInstance().(*protocolsunlynx.AddRmServerProtocol).Add = sim.Add
		root.ProtocolInstance().(*protocolsunlynx.AddRmServerProtocol).KeyToRm = newSecKey

		round := libunlynx.StartTimer("_LocalAddRm(Simulation")

		if err := root.Start(); err != nil {
			log.Fatal("Error while starting <LocalAddRm> Protocol")
		}
		results := <-root.ProtocolInstance().(*protocolsunlynx.AddRmServerProtocol).FeedbackChannel
		log.Lvl1("Number of aggregated lines: ", len(results))

		libunlynx.EndTimer(round)

	}

	return nil
}
