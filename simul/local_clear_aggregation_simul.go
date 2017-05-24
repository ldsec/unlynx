package main

import (
	"github.com/BurntSushi/toml"
	"github.com/LCA1/UnLynx/protocols"
	"github.com/LCA1/UnLynx/services/data"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/simul/monitor"
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

	log.LLvl1("Setup done")

	return sc, nil
}

// Run starts the simulation.
func (sim *LocalClearAggregationSimulation) Run(config *onet.SimulationConfig) error {
	for round := 0; round < sim.Rounds; round++ {
		log.LLvl1("Starting round", round)
		rooti, err := config.Overlay.CreateProtocol("LocalClearAggregation", config.Tree, onet.NilServiceID)
		if err != nil {
			return err
		}

		root := rooti.(*protocols.LocalClearAggregationProtocol)

		types := make([]int64, sim.NbrGroupAttributes)
		data.FillInt64Slice(types, 1)
		if len(types) > 0 {
			types[0] = int64(sim.NbrGroups)
		}

		testData := data.GenerateData(1, int64(sim.NbrResponses), int64(sim.NbrResponses), int64(sim.NbrGroupAttributes), 0,
			int64(sim.NbrWhereAttributes), 0, int64(sim.NbrAggrAttributes), 0, types, true)

		log.LLvl1("starting protocol with ", len(testData), " responses")

		//protocol
		root.ProtocolInstance().(*protocols.LocalClearAggregationProtocol).TargetOfAggregation = testData["0"]

		round := monitor.NewTimeMeasure("LocalClearAggregation(SIMULATION)")
		root.Start()
		results := <-root.ProtocolInstance().(*protocols.LocalClearAggregationProtocol).FeedbackChannel
		log.LLvl1("Number of aggregated lines (groups): ", len(results))

		// Test Simulation
		if data.CompareClearResponses(data.ComputeExpectedResult(testData, 1, false), results) {
			log.LLvl1("Result is right! :)")
		} else {
			log.LLvl1("Result is wrong! :(")
		}
		round.Record()
	}

	return nil
}
