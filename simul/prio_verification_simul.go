package main

import (
	"github.com/BurntSushi/toml"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"

	"crypto/rand"
	"errors"
	"math/big"
	"unlynx/lib"

	"github.com/henrycg/prio/circuit"
	"github.com/henrycg/prio/share"
	"github.com/henrycg/prio/utils"
	"unlynx/lib/prioUtils"

	"github.com/henrycg/prio/config"
	"os"
	"time"
	"unlynx/protocols/prio"
)

//variable to choose the secret once and split them, as you assume client have their secret already split
//in  a vector of size #servers. Means the number of server is supposed to be public
var ckt []*circuit.Circuit
var req []*prioUtils.Request
var mod = share.IntModulus
var randomPoint = utils.RandInt(mod)
var secretBitLen []int64

//function to generate random value and their splits

//PrioVerificationSimulation holds the state of a simulation.
type PrioVerificationSimulation struct {
	onet.SimulationBFTree

	NbrRequestByProto int
	NbrValidation     int
	Proofs            bool
}

func init() {
	onet.SimulationRegister("PrioVerification", NewPrioVerificationSimulation)
}

//NewPrioVerificationSimulation creates a new Prio Verification Simulation
func NewPrioVerificationSimulation(config string) (onet.Simulation, error) {
	sim := &PrioVerificationSimulation{}
	_, err := toml.Decode(config, sim)
	if err != nil {
		return nil, err
	}

	return sim, nil
}

//Setup create the local roster for simulation
func (sim *PrioVerificationSimulation) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	sc := &onet.SimulationConfig{}
	sim.CreateRoster(sc, hosts, 2000)
	err := sim.CreateTree(sc)

	if err != nil {
		return nil, err
	}

	log.Lvl1("Setup done")

	return sc, nil
}

//Node creates the protocol at each nodes.
func (sim *PrioVerificationSimulation) Node(config *onet.SimulationConfig) error {
	//start := time.Now()
	config.Server.ProtocolRegister("PrioVerificationSimul",
		func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
			return NewPrioVerificationProtocolSimul(tni, sim)
		})
	//time := time.Since(start)
	//sum += time.Seconds()

	return sim.SimulationBFTree.Node(config)
}

//Run starts the simulation.
func (sim *PrioVerificationSimulation) Run(config *onet.SimulationConfig) error {
	for round := 0; round < sim.Rounds; round++ {
		log.Lvl1("Starting round", round)

		req, ckt = createCipherSet(sim.NbrRequestByProto, config.Tree.Size())

		roundTime := lib.StartTimer("PrioVerification(Simulation")
		//new variable for nbValidation
		wg := lib.StartParallelize(sim.NbrValidation)
		start := time.Now()
		for i := 0; i < sim.NbrValidation; i++ {
			go func() {
				defer wg.Done()
				rooti, err := config.Overlay.CreateProtocol("PrioVerificationSimul", config.Tree, onet.NilServiceID)
				if err != nil {
					return
				}
				root := rooti.(*prio.PrioVerificationProtocol)

				root.Start()
				<-root.AggregateData

			}()

		}
		lib.EndParallelize(wg)
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

	}
	return nil
}

//NewPrioVerificationProtocolSimul is the function called on each node to send data
func NewPrioVerificationProtocolSimul(tni *onet.TreeNodeInstance, sim *PrioVerificationSimulation) (onet.ProtocolInstance, error) {

	protocol, err := prio.NewPrioVerifcationProtocol(tni)
	pap := protocol.(*prio.PrioVerificationProtocol)

	pap.Request = new(prioUtils.Request)
	pap.Checker = new(prioUtils.Checker)
	pap.Pre = new(prioUtils.CheckerPrecomp)

	//simulate sending of client to protocol, !! each server must have a different circuit which has the same value for
	//each client submission

	pap.Request = req[pap.Index()]
	pap.Checker = prioUtils.NewChecker(ckt[tni.Index()], pap.Index(), 0)
	pap.Pre = prioUtils.NewCheckerPrecomp(ckt[tni.Index()])
	pap.Pre.SetCheckerPrecomp(randomPoint)

	return protocol, err
}

//create cipher text for test from a config file in Prio
func createCipherSet(numberClient, numberServer int) ([]*prioUtils.Request, []*circuit.Circuit) {

	circuit := make([]*circuit.Circuit, 0)
	result := make([]*prioUtils.Request, numberServer)
	secretBitLen = make([]int64, numberServer)

	secret := config.LoadFile("/home/max/Documents/go/src/prio/eval/cell-geneva.conf")
	fields := make([]*config.Field, 0)
	for j := 0; j < len(secret.Fields); j++ {
		fields = append(fields, &(secret.Fields[j]))
	}
	result = prioUtils.ClientRequest(fields, numberServer, 0)

	for j := 0; j < numberServer; j++ {

		test := prioUtils.ConfigToCircuit(fields)
		circuit = append(circuit, test)
	}

	return result, circuit
}

//fucntion to generate a random big int between 0 and low^expo
func randomBig(low, expo *big.Int) (int *big.Int) {
	max := new(big.Int)
	max.Exp(low, expo, nil).Sub(max, big.NewInt(1))

	//Generate cryptographically strong pseudo-random between 0 - max
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		log.Lvl2(errors.New("Could not create random Big int "))
	}
	return n
}
