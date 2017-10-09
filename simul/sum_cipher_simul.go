package main

import (
	"gopkg.in/dedis/onet.v1"
	"github.com/BurntSushi/toml"
	"gopkg.in/dedis/onet.v1/log"
	"unlynx/protocols"

	"math/big"
	"crypto/rand"
	"errors"
)


func createCipherSet(numberClient, numberServer int) (map[*big.Int][]*big.Int,*big.Int) {

	//secret value of clients, and the map of secret value to shares
	Secrets := make([]*big.Int,numberClient)
	SecretsToShare := make(map[*big.Int][]*big.Int)

	//modulus is set in function of the whole data miust be > nbClient*2^b
	Modulus := big.NewInt(0)

	MaxNumberBits :=0
	for i :=0; i < numberClient ;i++ {
		Secrets[i] = randomBig(big.NewInt(int64(2)),big.NewInt(int64(32)))
		if Secrets[i].BitLen() > MaxNumberBits {
			MaxNumberBits = Secrets[i].BitLen()
		}
	}
	//create the modulus
	helper := new(big.Int)
	Modulus.Mul(big.NewInt(int64(numberClient)),helper.Exp(big.NewInt(int64(2)),big.NewInt(int64(MaxNumberBits)),nil))

	//create the shares
	for i,_ := range Secrets {
		SecretsToShare[Secrets[i]] = protocols.Share(Modulus,numberServer,Secrets[i])
	}
	return SecretsToShare,Modulus
}

func distributeShare()(error) {
	return nil
}

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
	Modulus			*big.Int
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

	return nil
}

func NewSumCipherProtocolSimul(tni *onet.TreeNodeInstance, sim *SumCipherSimulation) (onet.ProtocolInstance, error) {
	protocol, err := protocols.NewSumCipherProtocol(tni)
	pap := protocol.(*protocols.ProtocolSumCipher)

	_,mod := createCipherSet(sim.NbrClient, sim.NbrServ)
	//pap.Ciphers = data
	pap.Modulus = mod
	return pap, err
}
