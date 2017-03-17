package main

import (
	"github.com/BurntSushi/toml"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"

	"strconv"
	"sync"
	"gopkg.in/dedis/onet.v1/simul/monitor"
	"github.com/JoaoAndreSa/MedCo/services"
	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/JoaoAndreSa/MedCo/services/data"
)

//Defines the simulation for the service-medCo to be run with cothority/simul.
func init() {
	onet.SimulationRegister("ServiceMedCo", NewSimulationMedCo)
}

// SimulationMedCo the state of a simulation.
type SimulationMedCo struct {
	onet.SimulationBFTree

	NbrDPs             	int     //number of clients (or in other words data holders)
	NbrResponsesTot    	int64   //number of survey entries (ClientClearResponse) per host
	NbrResponsesFiltered 	int64	//number of entries to be filtered (the ones we keep)
	NbrGroupsClear     	int64   //number of non-sensitive (clear) grouping attributes
	NbrGroupsEnc       	int64   //number of sensitive (encrypted) grouping attributes
	NbrWhereClear	   	int64	//number of non-sensitive (clear) where attributes
	NbrWhereEncrypted  	int64	//number of sensitive (encrypted) where attributes
	NbrGroupAttributes 	[]int64 //number of different groups inside each grouping attribute
	NbrAggrClear 		int64   //number of non-sensitive (clear) aggregating attributes
	NbrAggrEncrypted    	int64   //number of sensitive (encrypted) aggregating attributes
	Count 		   	bool	//toggle count queries
	RandomGroups       	bool    //generate data randomly or num entries == num groups (deterministically)
	DataRepetitions    	int     //repeat the number of entries x times (e.g. 1 no repetition; 1000 repetitions)
	Proofs             	bool    //with proofs of correctness everywhere
}

// NewSimulationMedCo constructs a full MedCo service simulation.
func NewSimulationMedCo(config string) (onet.Simulation, error) {
	es := &SimulationMedCo{}
	_, err := toml.Decode(config, es)
	if err != nil {
		return nil, err
	}
	return es, nil
}

// Setup creates the tree used for that simulation
func (sim *SimulationMedCo) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
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
func (sim *SimulationMedCo) Run(config *onet.SimulationConfig) error {
	var start *monitor.TimeMeasure
	log.SetDebugVisible(1)
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
		client := services.NewMedcoClient(el.List[0], strconv.Itoa(0))

		nbrDPs := make(map[string]int64)
		//how many data providers for each server
		for _, server := range el.List {
			nbrDPs[server.String()] = 1 // 1 DPs for each server
		}

		// Generate Survey Data
		sum := [sim.NbrAggrClear + sim.NbrAggrEncrypted]string{}
		for i := 0 ; i < (sim.NbrAggrClear + sim.NbrAggrEncrypted); i++{
			sum[i] = "sum"+strconv.Itoa(i)
		}
		count := sim.Count

		whereQueryValues := [sim.NbrWhereClear+sim.NbrWhereEncrypted]lib.WhereQueryAttribute{}
		pred := string{}
		counter := 0
		for i := 0 ; i < sim.NbrWhereClear+sim.NbrWhereEncrypted; i++{
			whereQueryValues[i] = lib.WhereQueryAttribute{"w"+strconv.Itoa(i), *lib.EncryptInt(el.Aggregate, 1)}
			pred = pred + " v" + strconv.Itoa(counter) + " == v" + strconv.Itoa(counter+1) + " &&"
			counter = counter + 2
		}

		groupBy := [sim.NbrGroupsClear+sim.NbrGroupsEnc]string{}
		for i := 0 ; i < sim.NbrGroupsClear+sim.NbrGroupsEnc; i++{
			groupBy[i] = "g"+strconv.Itoa(i)
		}

		surveyID, _, err := client.SendSurveyCreationQuery(el, lib.SurveyID("testSurvey"), lib.SurveyID(""), sum, count, whereQueryValues, pred, groupBy, nil, nil, nbrDPs, 0, sim.Proofs, false)

		if err != nil {
			log.Fatal("Service did not start.")
		}

		// RandomGroups (true/false) is to respectively generate random or non random entries
		//TODO change generate data
		testData := data.GenerateData(int64(sim.NbrDPs), sim.NbrResponsesTot, sim.NbrResponsesFiltered, sim.NbrGroupsClear, sim.NbrGroupsEnc,
			sim.NbrWhereClear, sim.NbrWhereEncrypted, sim.NbrAggrClear, sim.NbrAggrEncrypted, sim.NbrGroupAttributes, sim.RandomGroups)

		/// START SERVICE PROTOCOL
		if lib.TIME {
			start = monitor.NewTimeMeasure("SendingData")
		}

		log.Lvl1("Sending response data... ")
		dataHolder := make([]*services.API, sim.NbrDPs)
		wg := lib.StartParallelize(len(dataHolder))

		var mutexDH sync.Mutex
		for i, client := range dataHolder {
			start1 := lib.StartTimer(strconv.Itoa(i) + "_IndividualSendingData")
			if lib.PARALLELIZE {
				go func(i int, client *services.API) {
					mutexDH.Lock()
					data := testData[strconv.Itoa(i)]
					server := el.List[i%nbrHosts]
					mutexDH.Unlock()

					client = services.NewMedcoClient(server, strconv.Itoa(i+1))
					client.SendSurveyResponseQuery(*surveyID, data, el.Aggregate, sim.DataRepetitions, count)
					defer wg.Done()
				}(i, client)
			} else {
				start2 := lib.StartTimer(strconv.Itoa(i) + "_IndividualNewMedcoClient")

				client = services.NewMedcoClient(el.List[i%nbrHosts], strconv.Itoa(i+1))

				lib.EndTimer(start2)
				start3 := lib.StartTimer(strconv.Itoa(i) + "_IndividualSendSurveyResults")

				client.SendSurveyResponseQuery(*surveyID, testData[strconv.Itoa(i)], el.Aggregate, sim.DataRepetitions, count)

				lib.EndTimer(start3)

			}
			lib.EndTimer(start1)

		}
		lib.EndParallelize(wg)
		lib.EndTimer(start)

		start := lib.StartTimer("Simulation")

		grpClear, grp, aggr, err := client.SendSurveyResultsQuery(*surveyID)
		if err != nil {
			log.Fatal("Service could not output the results. ", err)
		}

		lib.EndTimer(start)
		// END SERVICE PROTOCOL

		// Print Output
		allData := make([]lib.DpClearResponse, 0)
		log.Lvl1("Service output:")
		for i := range *grp {
			log.Lvl1(i, ")", (*grpClear)[i], ",", (*grp)[i], "->", (*aggr)[i])
			//allData = append(allData, lib.DpClearResponse{GroupingAttributesClear: (*grpClear)[i], GroupingAttributesEnc: (*grp)[i], AggregatingAttributes: (*aggr)[i]})
		}

		// Test Service Simulation
		if data.CompareClearResponses(data.ComputeExpectedResult(testData, sim.DataRepetitions), allData) {
			log.LLvl1("Result is right! :)")
		} else {
			log.LLvl1("Result is wrong! :(")
		}
	}

	return nil
}
