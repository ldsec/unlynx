package main

import (
	"github.com/BurntSushi/toml"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/services"
	"github.com/lca1/unlynx/services/data"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/simul/monitor"
	"strconv"
)

//Defines the simulation for the service-medCo to be run with cothority/simul.
func init() {
	onet.SimulationRegister("ServiceUnLynx", NewSimulationUnLynx)
}

// SimulationUnLynx the state of a simulation.
type SimulationUnLynx struct {
	onet.SimulationBFTree

	NbrDPs               int     //number of clients (or in other words data holders)
	NbrResponsesTot      int64   //number of survey entries (ClientClearResponse) per host
	NbrResponsesFiltered int64   //number of entries to be filtered (the ones we keep)
	NbrGroupsClear       int64   //number of non-sensitive (clear) grouping attributes
	NbrGroupsEnc         int64   //number of sensitive (encrypted) grouping attributes
	NbrGroupAttributes   []int64 //number of different groups inside each grouping attribute
	NbrWhereClear        int64   //number of non-sensitive (clear) where attributes
	NbrWhereEncrypted    int64   //number of sensitive (encrypted) where attributes
	NbrAggrClear         int64   //number of non-sensitive (clear) aggregating attributes
	NbrAggrEncrypted     int64   //number of sensitive (encrypted) aggregating attributes
	Count                bool    //toggle count queries
	RandomGroups         bool    //generate data randomly or num entries == num groups (deterministically)
	DataRepetitions      int     //repeat the number of entries x times (e.g. 1 no repetition; 1000 repetitions)
	Proofs               bool    //with proofs of correctness everywhere
}

// NewSimulationUnLynx constructs a full UnLynx service simulation.
func NewSimulationUnLynx(config string) (onet.Simulation, error) {
	es := &SimulationUnLynx{}
	_, err := toml.Decode(config, es)
	if err != nil {
		return nil, err
	}
	return es, nil
}

// Setup creates the tree used for that simulation
func (sim *SimulationUnLynx) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
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
func (sim *SimulationUnLynx) Run(config *onet.SimulationConfig) error {
	var start *monitor.TimeMeasure
	// Setup Simulation
	nbrHosts := config.Tree.Size()
	log.Lvl1("Size:", nbrHosts, ", Rounds:", sim.Rounds)

	// Does not make sense to have more servers than clients!!
	if nbrHosts > sim.NbrDPs {
		log.Fatal("hosts:", nbrHosts, "must be the same or lower as num_clients:", sim.NbrDPs)
		return nil
	}
	el := (*config.Tree).Roster

	for round := 0; round < sim.Rounds; round++ {
		log.Lvl1("Starting round", round, el)
		client := serviceUnLynx.NewUnLynxClient(el.List[0], strconv.Itoa(0))

		// Define how many data providers for each server
		nbrDPs := make(map[string]int64)
		for _, server := range el.List {
			nbrDPs[server.String()] = 1 // 1 DP(s) for each server
		}

		// Generate Survey Data

		// Aggregating attributes
		NbrAggr := sim.NbrAggrClear + sim.NbrAggrEncrypted
		sum := make([]string, NbrAggr)
		for i := 0; i < int(NbrAggr); i++ {
			sum[i] = "s" + strconv.Itoa(i)
		}
		count := sim.Count

		// Where attributes + predicate
		NbrWhere := sim.NbrWhereClear + sim.NbrWhereEncrypted
		whereQueryValues := make([]libUnLynx.WhereQueryAttribute, NbrWhere)

		predicate := ""
		counter := 0

		if int(NbrWhere) > 0 {
			for i := 0; i < int(NbrWhere); i++ {
				whereQueryValues[i] = libUnLynx.WhereQueryAttribute{Name: "w" + strconv.Itoa(i), Value: *libUnLynx.EncryptInt(el.Aggregate, 1)}
				predicate = predicate + " v" + strconv.Itoa(counter) + " == v" + strconv.Itoa(counter+1) + " &&"
				counter = counter + 2
			}
			// remove the last &&
			predicate = predicate[:len(predicate)-2]
		}

		// Group by attributes
		NbrGroups := sim.NbrGroupsClear + sim.NbrGroupsEnc
		groupBy := make([]string, NbrGroups)
		for i := 0; i < int(NbrGroups); i++ {
			groupBy[i] = "g" + strconv.Itoa(i)
		}

		surveyID, err := client.SendSurveyCreationQuery(el, serviceUnLynx.SurveyID(""), nil, nbrDPs, sim.Proofs, false, sum, count, whereQueryValues, predicate, groupBy)

		if err != nil {
			log.Fatal("Service did not start.")
		}

		// RandomGroups (true/false) is to respectively generate random or non random entries
		testData := dataUnLynx.GenerateData(int64(sim.NbrDPs), sim.NbrResponsesTot, sim.NbrResponsesFiltered, sim.NbrGroupsClear, sim.NbrGroupsEnc,
			sim.NbrWhereClear, sim.NbrWhereEncrypted, sim.NbrAggrClear, sim.NbrAggrEncrypted, sim.NbrGroupAttributes, sim.RandomGroups)

		/*log.Lvl1("Saving test data...")
		data.WriteDataToFile("unlynx_test_data.txt", testData)*/

		/// START SERVICE PROTOCOL
		if libUnLynx.TIME {
			start = monitor.NewTimeMeasure("SendingData")
		}

		log.Lvl1("Sending response data... ")
		dataHolder := make([]*serviceUnLynx.API, sim.NbrDPs)
		wg := libUnLynx.StartParallelize(len(dataHolder))

		for i, client := range dataHolder {
			start1 := libUnLynx.StartTimer(strconv.Itoa(i) + "_IndividualSendingData")
			if libUnLynx.PARALLELIZE {
				go func(i int, client *serviceUnLynx.API) {
					dataCollection := testData[strconv.Itoa(i)]
					server := el.List[i%nbrHosts]

					client = serviceUnLynx.NewUnLynxClient(server, strconv.Itoa(i+1))
					client.SendSurveyResponseQuery(*surveyID, dataCollection, el.Aggregate, sim.DataRepetitions, count)
					defer wg.Done()
				}(i, client)
			} else {
				start2 := libUnLynx.StartTimer(strconv.Itoa(i) + "_IndividualNewUnLynxClient")

				client = serviceUnLynx.NewUnLynxClient(el.List[i%nbrHosts], strconv.Itoa(i+1))

				libUnLynx.EndTimer(start2)
				start3 := libUnLynx.StartTimer(strconv.Itoa(i) + "_IndividualSendSurveyResults")

				client.SendSurveyResponseQuery(*surveyID, testData[strconv.Itoa(i)], el.Aggregate, sim.DataRepetitions, count)

				libUnLynx.EndTimer(start3)

			}
			libUnLynx.EndTimer(start1)

		}
		libUnLynx.EndParallelize(wg)
		libUnLynx.EndTimer(start)

		start := libUnLynx.StartTimer("Simulation")

		grp, aggr, err := client.SendSurveyResultsQuery(*surveyID)
		if err != nil {
			log.Fatal("Service could not output the results. ", err)
		}

		libUnLynx.EndTimer(start)
		// END SERVICE PROTOCOL

		// Print Output
		allData := make([]libUnLynx.DpClearResponse, 0)
		log.Lvl1("Service output:")
		for i := range *grp {
			log.Lvl1(i, ")", (*grp)[i], "->", (*aggr)[i])
			allData = append(allData, libUnLynx.DpClearResponse{GroupByClear: libUnLynx.ConvertDataToMap((*grp)[i], "g", 0), AggregatingAttributesClear: libUnLynx.ConvertDataToMap((*aggr)[i], "s", 0)})
		}

		// Test Service Simulation
		if dataUnLynx.CompareClearResponses(dataUnLynx.ComputeExpectedResult(testData, sim.DataRepetitions, true), allData) {
			log.Lvl1("Result is right! :)")
		} else {
			log.Lvl1("Result is wrong! :(")
		}
	}

	return nil
}
