package main

import (
	"github.com/BurntSushi/toml"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/simul/monitor"
	"github.com/lca1/unlynx/protocols/utils"
	"github.com/lca1/unlynx/services/default/data"
)

func init() {
	onet.SimulationRegister("LocalClearAggregation", NewLocalClearAggregationSimulation)

}

// LocalClearAggregationSimulation the state of a simulation.
type LocalClearAggregationSimulation struct {
	onet.SimulationBFTree

	NbrResponses       int
	NbrGroups          int
	NbrGroupAttributes int //to make sense all the different attributes are encrypted
	NbrWhereAttributes int
	NbrAggrAttributes  int
	Proofs             bool
}

// NewLocalClearAggregationSimulation constructs a local aggregation simulation (using clear data).
func NewLocalClearAggregationSimulation(config string) (onet.Simulation, error) {
	sim := &LocalClearAggregationSimulation{}
	_, err := toml.Decode(config, sim)

	if err != nil {
		return nil, err
	}
	return sim, nil
}

// Setup initializes the simulation.
func (sim *LocalClearAggregationSimulation) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
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
func (sim *LocalClearAggregationSimulation) Run(config *onet.SimulationConfig) error {
	for round := 0; round < sim.Rounds; round++ {
		log.Lvl1("Starting round", round)
		rooti, err := config.Overlay.CreateProtocol("LocalClearAggregation", config.Tree, onet.NilServiceID)
		if err != nil {
			return err
		}

		root := rooti.(*protocolsunlynxutils.LocalClearAggregationProtocol)

		types := make([]int64, sim.NbrGroupAttributes)
		dataunlynx.FillInt64Slice(types, 1)
		if len(types) > 0 {
			types[0] = int64(sim.NbrGroups)
		}

		testData := dataunlynx.GenerateData(1, int64(sim.NbrResponses), int64(sim.NbrResponses), int64(sim.NbrGroupAttributes), 0,
			int64(sim.NbrWhereAttributes), 0, int64(sim.NbrAggrAttributes), 0, types, true)

		log.Lvl1("starting protocol with ", len(testData), " responses")

		//protocol
		root.ProtocolInstance().(*protocolsunlynxutils.LocalClearAggregationProtocol).TargetOfAggregation = testData["0"]

		round := monitor.NewTimeMeasure("LocalClearAggregation(SIMULATION)")
		if err := root.Start(); err != nil {
			log.Fatal("Error while starting <LocalClearAggregation> Protocol:", err)
		}
		results := <-root.ProtocolInstance().(*protocolsunlynxutils.LocalClearAggregationProtocol).FeedbackChannel
		log.Lvl1("Number of aggregated lines (groups): ", len(results))

		// Test Simulation
		if dataunlynx.CompareClearResponses(dataunlynx.ComputeExpectedResult(testData, 1, false), results) {
			log.Lvl1("Result is right! :)")
		} else {
			log.Lvl1("Result is wrong! :(")
		}
		round.Record()
	}

	return nil
}
