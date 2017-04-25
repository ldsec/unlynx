package main

import (
	"github.com/BurntSushi/toml"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
	"strconv"
	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/JoaoAndreSa/MedCo/services/i2b2"
	"github.com/JoaoAndreSa/MedCo/services/data"
	"sync"
	//"time"
)

//Defines the simulation for the service-medCo to be run with cothority/simul.
func init() {
	onet.SimulationRegister("ServiceMedCoI2B2", NewSimulationMedCoI2B2)
}

// SimulationMedCo the state of a simulation.
type SimulationMedCoI2B2 struct {
	onet.SimulationBFTree

	NbrDPs               int     //number of clients (or in other words data holders)
	NbrResponsesTot      int64   //number of survey entries (ClientClearResponse) per host
	NbrResponsesFiltered int64   //number of entries to be filtered (the ones we keep)
	NbrWhereClear        int64   //number of non-sensitive (clear) where attributes
	NbrWhereEncrypted    int64   //number of sensitive (encrypted) where attributes
	NbrAggrClear         int64   //number of non-sensitive (clear) aggregating attributes
	NbrAggrEncrypted     int64   //number of sensitive (encrypted) aggregating attributes
	Count                bool    //toggle count queries
	RandomGroups         bool    //generate data randomly or num entries == num groups (deterministically)
	DataRepetitions      int     //repeat the number of entries x times (e.g. 1 no repetition; 1000 repetitions)
	Proofs               bool    //with proofs of correctness everywhere
	QueryMode	     int64   //define the query mode (1 result per data provider or one single aggregated result)
}

// NewSimulationMedCoI2B2 constructs a full MedCoI2B2 service simulation.
func NewSimulationMedCoI2B2(config string) (onet.Simulation, error) {
	es := &SimulationMedCoI2B2{}
	_, err := toml.Decode(config, es)
	if err != nil {
		return nil, err
	}
	return es, nil
}

// Setup creates the tree used for that simulation
func (sim *SimulationMedCoI2B2) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
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
func (sim *SimulationMedCoI2B2) Run(config *onet.SimulationConfig) error {
	//var start *monitor.TimeMeasure
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

	// querier public and private keys
	secKey := network.Suite.Scalar().Pick(random.Stream)
	pubKey := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)



	for round := 0; round < sim.Rounds; round++ {
		log.Lvl1("Starting round", round, el)

		nbrDPs := make(map[string]int64)
		clients := make([]*serviceI2B2.API,0)
		for i:= 0; i<sim.NbrDPs; i++ {
			index := i%sim.Hosts

			clients = append(clients,serviceI2B2.NewMedcoClient(el.List[index], strconv.Itoa(i%sim.NbrDPs)))

			if _, exists := nbrDPs[el.List[index].String()]; exists {
				current := nbrDPs[el.List[index].String()]
				nbrDPs[el.List[index].String()] = current + 1
			} else {
				nbrDPs[el.List[index].String()] = 1
			}
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
		whereQueryValues := make([]lib.WhereQueryAttribute, NbrWhere)

		var predicate string
		counter := 0
		for i := 0; i < int(NbrWhere); i++ {
			whereQueryValues[i] = lib.WhereQueryAttribute{Name: "w" + strconv.Itoa(i), Value: *lib.EncryptInt(el.Aggregate, 1)}
			predicate = predicate + " v" + strconv.Itoa(counter) + " == v" + strconv.Itoa(counter+1) + " &&"
			counter = counter + 2
		}
		// remove the last &&
		predicate = predicate[:len(predicate)-2]

		// RandomGroups (true/false) is to respectively generate random or non random entries
		testData := data.GenerateData(int64(sim.NbrDPs), sim.NbrResponsesTot, sim.NbrResponsesFiltered, int64(0), int64(0),
			sim.NbrWhereClear, sim.NbrWhereEncrypted, sim.NbrAggrClear, sim.NbrAggrEncrypted, []int64{}, true)

		/*log.LLvl1("Saving test data...")
		data.WriteDataToFile("medco_test_data.txt", testData)*/

		finalResult := make([]int64, 0)
		mutex := &sync.Mutex{}

		wg := lib.StartParallelize(len(clients))

		for i,v := range clients {
			go func(i int, dp *serviceI2B2.API, aggregate abstract.Point) {
				defer wg.Done()

				clientData := testData[strconv.Itoa(i)]
				processData := make([]lib.ProcessResponse,0)

				for _,elem := range clientData{
					processData = append(processData,elem.FromDpClearResponseToProcess(aggregate))
				}
				_, result, _ :=  dp.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, false, sum, count, whereQueryValues, predicate, []string{}, processData, sim.QueryMode)

				mutex.Lock()
				resultClear := lib.DecryptIntVector(secKey, &result.AggregatingAttributes)
				finalResult = append(finalResult,resultClear...)
				mutex.Unlock()

			}(i, v, el.Aggregate)

		}

		lib.EndParallelize(wg)
		// END SERVICE PROTOCOL

		// Print Output
		log.LLvl1(finalResult)

		// Test Service I2B2 Simulation
		finalExpectedResult := make([]int64, 0)
		for k,v := range testData {
			map1DP := make(map[string][]lib.DpClearResponse,0)
			map1DP[k] = v
			expectedResults := data.ComputeExpectedResult(map1DP, sim.DataRepetitions, true)

			tmp := make([]int64, 0)
			tmp = lib.ConvertMapToData(expectedResults[0].AggregatingAttributesClear,"s",0)
			tmp = append(tmp,lib.ConvertMapToData(expectedResults[0].AggregatingAttributesEnc,"s",len(expectedResults[0].AggregatingAttributesClear))...)

			finalExpectedResult = append(finalExpectedResult,tmp...)
		}

		// if query mode == 1 it means the results are aggregated by the servers
		if sim.QueryMode == int64(1) {
			aggrResult := make([]int64,NbrAggr)
			for i,v := range finalExpectedResult{
				index := int64(i)%NbrAggr
				aggrResult[index] += v
			}

			for i := range finalExpectedResult{
				index := int64(i)%NbrAggr
				finalExpectedResult[i]=aggrResult[index]
			}
		}

		if len(finalResult) != len(finalExpectedResult) {
			log.Fatal("The size of the result is different")
		}

		var check bool
		for _, ev := range finalExpectedResult {
			check = false
			for _, fr := range finalResult {
				if ev == fr {
					check = true
				}
			}

			if !check {
				break
			}
		}

		if !check {
			log.LLvl1("Result is wrong! :(")
		} else {
			log.LLvl1("Result is right! :)")
		}
	}
	return nil
}
