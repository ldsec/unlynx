package main

import (
	"github.com/BurntSushi/toml"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/protocols"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
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

		//generate set of grouping attributes (for this protocol they should all be encrypted)
		group := make(map[string]libunlynx.CipherText)
		for i := 0; i < sim.NbrGroupAttributes; i++ {
			group[""+strconv.Itoa(i)] = *libunlynx.EncryptInt(pubKey, 1)
		}

		//generate set of aggregating attributes (for this protocol they should all be encrypted)
		aggr := make(map[string]libunlynx.CipherText)
		for i := 0; i < sim.NbrAggrAttributes; i++ {
			aggr[""+strconv.Itoa(i)] = *libunlynx.EncryptInt(pubKey, 1)
		}

		//generate set of where attributes (for this protocol they should all be encrypted)
		where := make(map[string]libunlynx.CipherText)
		for i := 0; i < sim.NbrWhereAttributes; i++ {
			where[""+strconv.Itoa(i)] = *libunlynx.EncryptInt(pubKey, 1)
		}

		cr := libunlynx.DpResponse{GroupByEnc: group, AggregatingAttributesEnc: aggr, WhereEnc: where}
		detResponses := make([]libunlynx.DpResponse, 0)
		for i := 0; i < sim.NbrResponses; i++ {
			detResponses = append(detResponses, cr)
		}

		log.Lvl1("starting protocol with ", len(detResponses), " responses")

		root.ProtocolInstance().(*protocolsunlynx.AddRmServerProtocol).TargetOfTransformation = detResponses
		root.ProtocolInstance().(*protocolsunlynx.AddRmServerProtocol).Proofs = sim.Proofs
		root.ProtocolInstance().(*protocolsunlynx.AddRmServerProtocol).Add = sim.Add
		root.ProtocolInstance().(*protocolsunlynx.AddRmServerProtocol).KeyToRm = newSecKey

		round := libunlynx.StartTimer("_LocalAddRm(Simulation")

		root.Start()
		results := <-root.ProtocolInstance().(*protocolsunlynx.AddRmServerProtocol).FeedbackChannel
		log.Lvl1("Number of aggregated lines: ", len(results))

		libunlynx.EndTimer(round)

	}

	return nil
}
