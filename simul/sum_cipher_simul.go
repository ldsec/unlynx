package main

import (
	"gopkg.in/dedis/onet.v1"
	"github.com/BurntSushi/toml"
	"gopkg.in/dedis/onet.v1/log"
	"unlynx/protocols"
	"math/big"
	"crypto/rand"
	"errors"
	"unlynx/lib"

	"os"
	"time"
	"unlynx/prio_utils"
	"github.com/henrycg/prio/share"
	"github.com/henrycg/prio/utils"
	"github.com/henrycg/prio/circuit"
)


//variable to choose the secret once and split them, as you assume client have their secret already split
//in  a vector of size #servers. Means the number of server is supposed to be public
var ckt [][]*circuit.Circuit
var req [][]*prio_utils.Request
var mod = share.IntModulus
var randomPoint = utils.RandInt(mod)
var secretBitLen [][]int
//function to generate random value and their splits

func createCipherSet(numberClient, numberServer int) ([][]*prio_utils.Request,[][]*circuit.Circuit) {

	//secret value of clients
	secretValues := make([][]*big.Int, numberClient)
	circuit := make([][]*circuit.Circuit,numberClient)
	result := make([][]*prio_utils.Request,numberClient)
	secretBitLen = make([][]int, numberClient)

	for i := 0; i < len(secretValues); i++ {
		secretValues[i] = prio_utils.Share(share.IntModulus, numberServer, randomBig(big.NewInt(2),big.NewInt(64)))
		result[i] = prio_utils.ClientRequest(secretValues[i],0)
		secretBitLen[i] = toBit(secretValues[i])
		for j:=0;j<numberServer ;j++  {
			test := prio_utils.ConfigToCircuitBit(secretBitLen[i])
			circuit[i] = append(circuit[i],test)
		}
	}

	return result,circuit
}

//fucntion to generate a random big int between 0 and low^expo
func randomBig (low,expo *big.Int)(int *big.Int){
	max := new(big.Int)
	max.Exp(low, expo, nil).Sub(max, big.NewInt(1))

	//Generate cryptographically strong pseudo-random between 0 - max
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		errors.New("Could not create random Big int ")
	}
	return n
}


func init() {
	onet.SimulationRegister("SumCipher", NewSumCipherSimulation)
}

// CollectiveAggregationSimulation holds the state of a simulation.
type SumCipherSimulation struct {
	onet.SimulationBFTree

	NbrClient          int
	Proofs             bool
}


func NewSumCipherSimulation(config string) (onet.Simulation, error) {
	sim := &SumCipherSimulation{}
	_, err := toml.Decode(config, sim)
	if err != nil {
		return nil, err
	}

	return sim, nil
}

func (sim *SumCipherSimulation) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
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
func (sim *SumCipherSimulation) Run(config *onet.SimulationConfig) error {
	for round := 0; round < sim.Rounds; round++ {

		log.Lvl1("Starting round", round)

		req,ckt = createCipherSet(sim.NbrClient, config.Tree.Size())

		rooti, err := config.Overlay.CreateProtocol("SumCipherSimul", config.Tree, onet.NilServiceID)

		if err != nil {
			return err
		}

		root := rooti.(*protocols.SumCipherProtocol)

		round := lib.StartTimer("_LocalAddRm(Simulation")
		start := time.Now()
		root.Start()
		results := <-root.ProtocolInstance().(*protocols.SumCipherProtocol).Feedback
		time := time.Since(start)
		log.Lvl1(sum)
		log.Lvl1("Aggregated result is : ", results)

		//expectedRes := big.NewInt(0)
		/*for _,c := range Secrets {
			expectedRes.Add(expectedRes,c)
			expectedRes.Mod(expectedRes,mod)
		}
		if !(expectedRes.Int64()==results.Int64()) {
			panic("Result is not matching")
		}*/
		lib.EndTimer(round)
		filename:="/home/max/Documents/go/src/unlynx/simul/time"
		f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			panic(err)
		}

		defer f.Close()

		if _, err = f.WriteString(time.String()+"\n"); err != nil {
			panic(err)
		}
	}
	return nil
}

func (sim *SumCipherSimulation) Node(config *onet.SimulationConfig) error {
	//start := time.Now()
	config.Server.ProtocolRegister("SumCipherSimul",
		func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
			return NewSumCipherProtocolSimul(tni, sim)
		})
	//time := time.Since(start)
	//sum += time.Seconds()

	return sim.SimulationBFTree.Node(config)
}

//function called on each node to send data
func NewSumCipherProtocolSimul(tni *onet.TreeNodeInstance, sim *SumCipherSimulation) (onet.ProtocolInstance, error) {

	protocol, err := protocols.NewSumCipherProtocol(tni)
	pap := protocol.(*protocols.SumCipherProtocol)

	pap.Modulus = mod
	pap.Proofs = true
	pap.Request = make([]*prio_utils.Request,len(req))
	pap.Checker = make([]*prio_utils.Checker,len(req))
	pap.Pre = make([]*prio_utils.CheckerPrecomp,len(req))

	//simulate sending of client to protocol, !! each server must have a different circuit which has the same value for
	//each client submission
	for i:=0; i<len(pap.Checker); i++ {
		pap.Request[i] = req[i][pap.Index()]
		pap.Checker[i] = prio_utils.NewChecker(ckt[i][tni.Index()],pap.Index(),0)
		pap.Pre[i] = prio_utils.NewCheckerPrecomp(ckt[i][tni.Index()])
		pap.Pre[i].SetCheckerPrecomp(randomPoint)
	}

	return protocol, err
}

func toBit(v []*big.Int)([]int) {
	result := make([]int,len(v))
	for i,k := range v {
		result[i] = k.BitLen()
	}
	return result
}