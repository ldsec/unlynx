package main

import (
	"github.com/BurntSushi/toml"
	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/JoaoAndreSa/MedCo/protocols"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"strconv"
)

func init() {
	onet.SimulationRegister("AddRmServer", NewAddRmSimulation)

}

// AddRmSimulation holds the state of a simulation.
type AddRmSimulation struct {
	onet.SimulationBFTree

	NbrResponses       int
	NbrGroupAttributes int //to make sense all the different attributes are encrypted
	NbrWhereAttributes int
	NbrAggrAttributes  int
	Proofs             bool
	Add                bool
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

		rooti, err := config.Overlay.CreateProtocol("AddRmServer", config.Tree, onet.NilServiceID)

		if err != nil {
			return err
		}

		root := rooti.(*protocols.AddRmServerProtocol)

		secKey := network.Suite.Scalar().Pick(random.Stream)
		newSecKey := network.Suite.Scalar().Pick(random.Stream)
		pubKey := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)

		//generate set of grouping attributes (for this protocol they should all be encrypted)
		group := make(map[string]lib.CipherText)
		for i := 0; i < sim.NbrGroupAttributes; i++ {
			group[""+strconv.Itoa(i)] = *lib.EncryptInt(pubKey, 1)
		}

		//generate set of aggregating attributes (for this protocol they should all be encrypted)
		aggr := make(map[string]lib.CipherText)
		for i := 0; i < sim.NbrAggrAttributes; i++ {
			aggr[""+strconv.Itoa(i)] = *lib.EncryptInt(pubKey, 1)
		}

		//generate set of where attributes (for this protocol they should all be encrypted)
		where := make(map[string]lib.CipherText)
		for i := 0; i < sim.NbrWhereAttributes; i++ {
			where[""+strconv.Itoa(i)] = *lib.EncryptInt(pubKey, 1)
		}

		cr := lib.DpResponse{GroupByEnc: group, AggregatingAttributesEnc: aggr, WhereEnc: where}
		detResponses := make([]lib.DpResponse, 0)
		for i := 0; i < sim.NbrResponses; i++ {
			detResponses = append(detResponses, cr)
		}

		log.LLvl1("starting protocol with ", len(detResponses), " responses")

		root.ProtocolInstance().(*protocols.AddRmServerProtocol).TargetOfTransformation = detResponses
		root.ProtocolInstance().(*protocols.AddRmServerProtocol).Proofs = sim.Proofs
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
