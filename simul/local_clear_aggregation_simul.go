package main

import (
	"github.com/BurntSushi/toml"
	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/JoaoAndreSa/MedCo/protocols"
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
	NbrGroupAttributes int
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

		root := rooti.(*protocols.LocalClearAggregationProtocol)

		//create data
		tab := make([]int64, sim.NbrAggrAttributes)
		for i := 0; i < len(tab); i++ {
			tab[i] = int64(1)
		}
		tabGr := make([]int64, sim.NbrGroupAttributes)
		for i := 0; i < len(tabGr); i++ {
			tabGr[i] = int64(1)
		}
		testData := make([]lib.DpClearResponse, 0)
		for i := 0; i < sim.NbrGroups; i++ {
			log.LLvl1("step: ", i, " / ", sim.NbrGroups, " in preparation")
			for j := 0; j < sim.NbrResponses/sim.NbrGroups; j++ {
				list := lib.DpClearResponse{GroupByClear: tabGr, GroupByEnc: nil, AggregatingAttributes: tab}
				testData = append(testData, list)
			}
		}
		log.LLvl1("starting protocol with ", len(testData), " responses")

		//protocol
		root.ProtocolInstance().(*protocols.LocalClearAggregationProtocol).TargetOfAggregation = testData

		round := monitor.NewTimeMeasure("LocalClearAggregation(SIMULATION)")
		root.Start()
		results := <-root.ProtocolInstance().(*protocols.LocalClearAggregationProtocol).FeedbackChannel
		log.LLvl1("Number of aggregated lines (groups): ", len(results))
		round.Record()
	}

	return nil
}
