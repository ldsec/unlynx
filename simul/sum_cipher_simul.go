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
)


var dataTest map[*big.Int][]*big.Int
var mod *big.Int
var Secrets []* big.Int

//function to generate random value and their splits
func createCipherSet(numberClient, numberServer int) (map[*big.Int][]*big.Int,*big.Int) {
	//secret value of clients, and the map of secret value to shares
	Secrets = make([]*big.Int,numberClient)
	SecretsToShare := make(map[*big.Int][]*big.Int)

	//modulus is set in function of the whole data miust be > nbClient*2^b
	Modulus := big.NewInt(0)

	helper := new(big.Int)
	Modulus.Mul(big.NewInt(int64(numberClient)),helper.Exp(big.NewInt(int64(2)),big.NewInt(int64(64)),nil))

	for i :=0; i < numberClient ;i++ {
		Secrets[i] = randomBig(big.NewInt(int64(2)),big.NewInt(int64(64)))
	}
	//create the modulus

	//create the shares
	for i,_ := range Secrets {
		SecretsToShare[Secrets[i]] = protocols.Share(Modulus,numberServer,Secrets[i])
	}
	return SecretsToShare,Modulus
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
	NbrServ			   int
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

		dataTest,mod = createCipherSet(sim.NbrClient, sim.NbrServ)
		rooti, err := config.Overlay.CreateProtocol("SumCipherSimul", config.Tree, onet.NilServiceID)

		if err != nil {
			return err
		}

		root := rooti.(*protocols.ProtocolSumCipher)

		//need to duplicate code to assign to root
		root.Modulus = mod
		ciph := make([]protocols.Cipher,sim.NbrClient)
		for i,_ := range Secrets {
			test := dataTest[Secrets[i]]
			ciph[i] = protocols.Encode(test[0])
		}
		root.Ciphers = ciph

		round := lib.StartTimer("_LocalAddRm(Simulation")

		root.Start()
		results := <-root.ProtocolInstance().(*protocols.ProtocolSumCipher).Feedback
		log.Lvl1("Aggregated result is : ", results)

		lib.EndTimer(round)
	}
	return nil
}

func (sim *SumCipherSimulation) Node(config *onet.SimulationConfig) error {
	config.Server.ProtocolRegister("SumCipherSimul",
		func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
			return NewSumCipherProtocolSimul(tni, sim)
		})

	return sim.SimulationBFTree.Node(config)
}

//function called on each node to send data
func NewSumCipherProtocolSimul(tni *onet.TreeNodeInstance, sim *SumCipherSimulation) (onet.ProtocolInstance, error) {

	protocol, err := protocols.NewSumCipherProtocol(tni)
	pap := protocol.(*protocols.ProtocolSumCipher)

	pap.Modulus = mod
	ciph := make([]protocols.Cipher,sim.NbrClient)
	for i,_ := range Secrets {
		test := dataTest[Secrets[i]]
		ciph[i] = protocols.Encode(test[tni.Index()])
	}

	pap.Ciphers = ciph
	return pap, err
}
