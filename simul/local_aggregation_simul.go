package main

import (
	"github.com/BurntSushi/toml"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/protocols"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

func init() {
	onet.SimulationRegister("LocalAggregation", NewLocalAggregationSimulation)

}

// LocalAggregationSimulation holds the state of a simulation.
type LocalAggregationSimulation struct {
	onet.SimulationBFTree

	NbrResponses       int
	NbrGroups          int
	NbrGroupAttributes int
	NbrAggrAttributes  int
	Proofs             bool
}

// NewLocalAggregationSimulation constructs a local aggregation simulation.
func NewLocalAggregationSimulation(config string) (onet.Simulation, error) {
	sim := &LocalAggregationSimulation{}
	_, err := toml.Decode(config, sim)

	if err != nil {
		return nil, err
	}
	return sim, nil
}

// Setup initializes the simulation.
func (sim *LocalAggregationSimulation) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
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
func (sim *LocalAggregationSimulation) Run(config *onet.SimulationConfig) error {
	for round := 0; round < sim.Rounds; round++ {
		log.Lvl1("Starting round", round)
		rooti, err := config.Overlay.CreateProtocol("LocalAggregation", config.Tree, onet.NilServiceID)
		if err != nil {
			return err
		}

		root := rooti.(*protocolsunlynx.LocalAggregationProtocol)

		secKey := network.Suite.Scalar().Pick(random.Stream)
		newSecKey := network.Suite.Scalar().Pick(random.Stream)
		pubKey := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)

		//create data
		tab := make([]int64, sim.NbrAggrAttributes)
		for i := 0; i < len(tab); i++ {
			tab[i] = int64(1)
		}
		tabGr := make([]int64, sim.NbrGroupAttributes)
		for i := 0; i < len(tabGr); i++ {
			tabGr[i] = int64(1)
		}

		// aggregation
		testCipherVect1 := *libunlynx.EncryptIntVector(pubKey, tab)
		groupCipherVect := *libunlynx.EncryptIntVector(pubKey, tabGr)
		detResponses := make([]libunlynx.FilteredResponseDet, 0)
		for i := 0; i < sim.NbrGroups; i++ {
			tmp := libunlynx.NewCipherVector(sim.NbrGroupAttributes)
			tmp.Add(groupCipherVect, groupCipherVect)
			groupCipherVect = *tmp
			cr := libunlynx.FilteredResponse{GroupByEnc: testCipherVect1, AggregatingAttributes: testCipherVect1}
			det1 := groupCipherVect
			det1.TaggingDet(secKey, newSecKey, pubKey, sim.Proofs)

			deterministicGroupAttributes := make(libunlynx.DeterministCipherVector, len(det1))
			for j, c := range det1 {
				deterministicGroupAttributes[j] = libunlynx.DeterministCipherText{Point: c.C}
			}

			newDetResponse := libunlynx.FilteredResponseDet{Fr: cr, DetTagGroupBy: deterministicGroupAttributes.Key()}
			log.Lvl1("step: ", i, " / ", sim.NbrGroups, " in preparation")
			for j := 0; j < sim.NbrResponses/sim.NbrGroups; j++ {
				detResponses = append(detResponses, newDetResponse)
			}
		}

		log.Lvl1("starting protocol with ", len(detResponses), " responses")

		root.ProtocolInstance().(*protocolsunlynx.LocalAggregationProtocol).TargetOfAggregation = detResponses
		root.ProtocolInstance().(*protocolsunlynx.LocalAggregationProtocol).Proofs = sim.Proofs

		round := libunlynx.StartTimer("_LocalAggregation(Simulation")

		root.Start()
		results := <-root.ProtocolInstance().(*protocolsunlynx.LocalAggregationProtocol).FeedbackChannel
		log.Lvl1("Number of aggregated lines: ", len(results))

		libunlynx.EndTimer(round)

	}

	return nil
}
