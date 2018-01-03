package main

import (
	"gopkg.in/dedis/onet.v1"
	"github.com/BurntSushi/toml"
	"gopkg.in/dedis/onet.v1/log"
	"unlynx/protocols"
	"math/big"
	"unlynx/lib"

	"unlynx/prio_utils"
	"github.com/henrycg/prio/share"

	"time"
	"os"
)


//variable to choose the secret once and split them, as you assume client have their secret already split
//in  a vector of size #servers. Means the number of server is supposed to be public

//function to generate random value and their splits
var aggData [][]*big.Int
var sumCipher *big.Int

func createAggData(numberClient, numberServer int) ([][]*big.Int) {

	//secret value of clients
	sumCipher = big.NewInt(0)
	result := make([][]*big.Int,numberServer)
	secretValues := make([][]*big.Int, numberClient)
	for i:= 0;i < numberClient ; i++ {
		secretValues[i] = prio_utils.Share(share.IntModulus, numberServer, randomBig(big.NewInt(2), big.NewInt(64)))
		log.LLvl1(secretValues)
		for j := 0; j < len(secretValues[i]); j++ {
			sumCipher.Add(sumCipher,secretValues[i][j])
			sumCipher.Mod(sumCipher,share.IntModulus)
		}
	}
	for k:=0;k<numberServer;k++ {
		for l:=0 ; l < numberClient;l++ {
			result[k] = append(result[k], secretValues[l][k])
		}
	}
	sumCipher.Mod(sumCipher,share.IntModulus)
	return result
}




func init() {
	onet.SimulationRegister("PrioAggregation", NewPrioAggregationSimulation)
}

// CollectiveAggregationSimulation holds the state of a simulation.
type PrioAggregationSimulation struct {
	onet.SimulationBFTree

	NbrRequestByProto  int
	Proofs             bool
}


func NewPrioAggregationSimulation(config string) (onet.Simulation, error) {
	sim := &PrioAggregationSimulation{}
	_, err := toml.Decode(config, sim)
	if err != nil {
		return nil, err
	}

	return sim, nil
}

func (sim *PrioAggregationSimulation) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	sc := &onet.SimulationConfig{}
	sim.CreateRoster(sc, hosts, 2000)
	err := sim.CreateTree(sc)

	if err != nil {
		return nil, err
	}

	log.Lvl1("Setup done")

	return sc, nil
}

func (sim *PrioAggregationSimulation) Node(config *onet.SimulationConfig) error {
	//start := time.Now()
	config.Server.ProtocolRegister("PrioAggregationSimul",
		func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
			return NewPrioAggregationProtocolSimul(tni, sim)
		})
	//time := time.Since(start)
	//sum += time.Seconds()

	return sim.SimulationBFTree.Node(config)
}



// Run starts the simulation.
func (sim *PrioAggregationSimulation) Run(config *onet.SimulationConfig) error {
	for round := 0; round < sim.Rounds; round++ {
		log.Lvl1("Starting round", round)

		aggData = createAggData(sim.NbrRequestByProto, config.Tree.Size())

		roundTime := lib.StartTimer("PrioAggregation(Simulation")
		//new variable for nbValidation
		//start := time.Now()


		rooti, err := config.Overlay.CreateProtocol("PrioAggregationSimul", config.Tree, onet.NilServiceID)
		if err != nil {
			return nil
		}
		start := time.Now()
		root := rooti.(*protocols.PrioAggregationProtocol)
		root.Start()
		result := <- root.Feedback
		log.Lvl1("res is " ,result)
		log.Lvl1(sumCipher)
		//time := time.Since(start)
		lib.EndTimer(roundTime)
		time := time.Since(start)
		lib.EndTimer(roundTime)
		filename := "/home/max/Documents/go/src/unlynx/simul/time"
		f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			panic(err)
		}

		defer f.Close()

		if _, err = f.WriteString(time.String() + "\n"); err != nil {
			panic(err)
		}

		/*filename := "/home/unlynx/go/src/unlynx/simul/time"
		f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			panic(err)
		}

		defer f.Close()

		if _, err = f.WriteString(time.String() + "\n"); err != nil {
			panic(err)
		}*/

	}
	return nil
}

//function called on each node to send data
func NewPrioAggregationProtocolSimul(tni *onet.TreeNodeInstance, sim *PrioAggregationSimulation) (onet.ProtocolInstance, error) {

	protocol, err := protocols.NewPrioAggregationProtocol(tni)
	pap := protocol.(*protocols.PrioAggregationProtocol)

	pap.Modulus = share.IntModulus
	pap.Shares = aggData[tni.Index()]


	return protocol, err
}
