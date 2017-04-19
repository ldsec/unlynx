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
)

// API represents a client with the server to which he is connected and its public/private key pair.
type Client struct {
	*serviceI2B2.API
	Public     abstract.Point
	Private    abstract.Scalar
}

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

	for round := 0; round < sim.Rounds; round++ {
		log.Lvl1("Starting round", round, el)

		nbrDPs := make(map[string]int64)
		clients := make([]Client,0)
		for i:= 0; i<sim.NbrDPs; i++ {
			index := i%sim.Hosts

			secKey := network.Suite.Scalar().Pick(random.Stream)

			clients = append(clients,Client{API: serviceI2B2.NewMedcoClient(el.List[index], strconv.Itoa(i%sim.NbrDPs)), Public: network.Suite.Point().Mul(network.Suite.Point().Base(), secKey), Private: secKey})

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

		// Group by attributes
		NbrGroups := sim.NbrGroupsClear + sim.NbrGroupsEnc
		groupBy := make([]string, NbrGroups)
		for i := 0; i < int(NbrGroups); i++ {
			groupBy[i] = "g" + strconv.Itoa(i)
		}

		// RandomGroups (true/false) is to respectively generate random or non random entries
		testData := data.GenerateData(int64(sim.NbrDPs), sim.NbrResponsesTot, sim.NbrResponsesFiltered, sim.NbrGroupsClear, sim.NbrGroupsEnc,
			sim.NbrWhereClear, sim.NbrWhereEncrypted, sim.NbrAggrClear, sim.NbrAggrEncrypted, sim.NbrGroupAttributes, sim.RandomGroups)

		/*log.LLvl1("Saving test data...")
		data.WriteDataToFile("medco_test_data.txt", testData)*/


		finalResult := make([]int64, 0)
		mutex := &sync.Mutex{}

		wg := lib.StartParallelize(len(clients))

		for i,client := range clients {
			go func(i int, pubKey abstract.Point, secKey abstract.Scalar) {
				defer wg.Done()

				clientData := testData[strconv.Itoa(i)]
				processData := make([]lib.ProcessResponse,0)

				for _,elem := range clientData{
					processData = append(processData,elem.FromDpClearResponseToProcess(pubKey))
				}
				_, result, _ :=  client.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), client.Public, nbrDPs, false, true, sum, count, whereQueryValues, predicate, groupBy, processData, 0)

				resultClear := lib.DecryptIntVector(secKey, &result.AggregatingAttributes)

				mutex.Lock()
				finalResult = append(finalResult,resultClear...)
				mutex.Unlock()

			}(i,client.Public,client.Private)

		}

		lib.EndParallelize(wg)
		// END SERVICE PROTOCOL

		// Print Output
		log.LLvl1(finalResult)

		// Test Service I2B2 Simulation
		expectedResults := data.ComputeExpectedResult(testData, sim.DataRepetitions, true)
		log.LLvl1(expectedResults)
	}
	return nil
}
