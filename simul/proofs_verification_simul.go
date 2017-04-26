package main

import (
	"github.com/BurntSushi/toml"
	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/JoaoAndreSa/MedCo/protocols"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"math"
)

func init() {
	onet.SimulationRegister("ProofsVerification", NewProofsVerificationSimulation)
}

// ProofsVerificationSimulation holds the state of a simulation.
type ProofsVerificationSimulation struct {
	onet.SimulationBFTree
	NbrServers         int
	NbrDPs             int
	NbrResponses       int
	NbrGroups          int
	NbrGroupAttributes int
	NbrAggrAttributes  int
}

// NewProofsVerificationSimulation constructs a key switching simulation.
func NewProofsVerificationSimulation(config string) (onet.Simulation, error) {
	sim := &ProofsVerificationSimulation{}
	_, err := toml.Decode(config, sim)
	if err != nil {
		return nil, err
	}
	return sim, nil
}

// Setup initializes the simulation.
func (sim *ProofsVerificationSimulation) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	sc := &onet.SimulationConfig{}
	sim.CreateRoster(sc, hosts, 2000)
	err := sim.CreateTree(sc)
	if err != nil {
		return nil, err
	}
	log.LLvl1("Setup done")
	return sc, nil
}

// Run starts the simulation.
func (sim *ProofsVerificationSimulation) Run(config *onet.SimulationConfig) error {

	for round := 0; round < sim.Rounds; round++ {
		log.LLvl1("Starting round", round)
		rooti, err := config.Overlay.CreateProtocol("ProofsVerification", config.Tree, onet.NilServiceID)
		if err != nil {
			return err
		}

		root := rooti.(*protocols.ProofsVerificationProtocol)
		secKey := network.Suite.Scalar().Pick(random.Stream)
		pubKey := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)
		secKeyNew := network.Suite.Scalar().Pick(random.Stream)
		pubKeyNew := network.Suite.Point().Mul(network.Suite.Point().Base(), secKeyNew)
		tab := make([]int64, sim.NbrAggrAttributes+sim.NbrGroupAttributes)

		// key switching **********************************************************
		for i := 0; i < len(tab); i++ {
			tab[i] = int64(1)
		}
		cipherVect := *lib.EncryptIntVector(pubKey, tab)

		origEphemKeys := make([]abstract.Point, len(cipherVect))
		origCipherVector := *lib.NewCipherVector(len(cipherVect))
		for i, v := range cipherVect {
			origEphemKeys[i] = v.K
			origCipherVector[i].C = v.C
		}

		switchedVect := lib.NewCipherVector(len(cipherVect))
		rs := switchedVect.KeySwitching(cipherVect, origEphemKeys, pubKeyNew, secKey)
		cps := lib.VectorSwitchKeyProofCreation(cipherVect, *switchedVect, rs, secKey, origEphemKeys, pubKeyNew)
		pskp := lib.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKey, Q: pubKeyNew}
		keySwitchingProofs := make([]lib.PublishedSwitchKeyProof, sim.NbrGroups)

		for i := range keySwitchingProofs {
			keySwitchingProofs[i] = pskp
		}

		// deterministic tagging ************************************************************
		tab = make([]int64, sim.NbrGroupAttributes)
		for i := 0; i < len(tab); i++ {
			tab[i] = int64(1)
		}
		cipherVect = *lib.EncryptIntVector(pubKey, tab)

		tagSwitchedVect := lib.NewCipherVector(len(cipherVect))
		tagSwitchedVect.DeterministicTagging(&cipherVect, secKey, secKeyNew)
		cps1 := lib.VectorDeterministicTagProofCreation(cipherVect, *tagSwitchedVect, secKeyNew, secKey)
		newContrib := network.Suite.Point().Mul(network.Suite.Point().Base(), secKeyNew)
		pdhp := lib.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *tagSwitchedVect, K: pubKey, SB: newContrib}
		deterministicTaggingProofs := make([]lib.PublishedDeterministicTaggingProof, sim.NbrResponses*sim.NbrServers)

		for i := range deterministicTaggingProofs {
			deterministicTaggingProofs[i] = pdhp
		}

		// deterministic tagging 2 ************************************************************
		tab = make([]int64, sim.NbrGroupAttributes)
		for i := 0; i < len(tab); i++ {
			tab[i] = int64(1)
		}
		cipherVect = *lib.EncryptIntVector(pubKey, tab)

		var deterministicTaggingAddProofs []lib.PublishedDetTagAdditionProof
		toAdd := network.Suite.Point().Mul(network.Suite.Point().Base(), secKeyNew)

		for i := range cipherVect {
			tmp := network.Suite.Point().Add(cipherVect[i].C, toAdd)
			prf := lib.DetTagAdditionProofCreation(cipherVect[i].C, secKeyNew, toAdd, tmp)
			deterministicTaggingAddProofs = append(deterministicTaggingAddProofs, prf)
		}

		oneVectorProofs := deterministicTaggingAddProofs
		for i := 0; i < (sim.NbrResponses*sim.NbrServers)-1; i++ {
			deterministicTaggingAddProofs = append(deterministicTaggingAddProofs, oneVectorProofs...)

		}

		// local aggregation **************************************************************
		tab = make([]int64, sim.NbrAggrAttributes)
		for i := 0; i < len(tab); i++ {
			tab[i] = int64(1)
		}
		cipherVect = *lib.EncryptIntVector(pubKey, tab)

		tab1 := make([]int64, sim.NbrGroupAttributes)
		for i := 0; i < len(tab1); i++ {
			tab1[i] = int64(1)
		}
		cipherVectGr := *lib.EncryptIntVector(pubKey, tab1)
		testCipherVect1 := *lib.EncryptIntVector(pubKey, tab)

		detResponses := make([]lib.FilteredResponseDet, 0)
		for i := 0; i < sim.NbrGroups; i++ {
			tmp := lib.NewCipherVector(sim.NbrGroupAttributes)
			tmp.Add(cipherVectGr, cipherVectGr)

			cipherVectGr = *tmp
			det1 := cipherVectGr
			det1.TaggingDet(secKey, secKey, pubKey, false)
			deterministicGroupAttributes := make(lib.DeterministCipherVector, len(det1))

			for j, c := range det1 {
				deterministicGroupAttributes[j] = lib.DeterministCipherText{Point: c.C}
			}

			newDetResponse := lib.FilteredResponseDet{Fr: lib.FilteredResponse{GroupByEnc: cipherVectGr, AggregatingAttributes: testCipherVect1}, DetTagGroupBy: deterministicGroupAttributes.Key()}
			for j := 0; j < (sim.NbrResponses/sim.NbrServers)/sim.NbrGroups; j++ {
				detResponses = append(detResponses, newDetResponse)
			}
		}

		comparisonMap := make(map[lib.GroupingKey]lib.FilteredResponse)
		for _, v := range detResponses {
			lib.AddInMap(comparisonMap, v.DetTagGroupBy, v.Fr)
		}

		PublishedAggregationProof := lib.AggregationProofCreation(detResponses, comparisonMap)
		aggregationProofs := make([]lib.PublishedAggregationProof, sim.NbrServers)
		for i := range aggregationProofs {
			aggregationProofs[i] = PublishedAggregationProof
		}

		//shuffling *****************************************************************************

		log.LLvl1("Starting shuffling (can take some time)")
		responsesToShuffle := make([]lib.ProcessResponse, sim.NbrResponses/sim.NbrServers)
		for i := 0; i < sim.NbrResponses/sim.NbrServers; i++ {
			responsesToShuffle[i] = lib.ProcessResponse{GroupByEnc: cipherVectGr, AggregatingAttributes: testCipherVect1}
		}

		clientResponsesShuffled, pi, beta := lib.ShuffleSequence(responsesToShuffle, nil, root.Roster().Aggregate, nil)
		log.LLvl1("Starting shuffling proof creation")
		shufflingProof := lib.ShufflingProofCreation(responsesToShuffle, clientResponsesShuffled, nil, root.Roster().Aggregate, beta, pi)
		shufflingProofs := make([]lib.PublishedShufflingProof, sim.NbrServers*sim.NbrServers)
		for i := range shufflingProofs {
			shufflingProofs[i] = shufflingProof
		}

		//collective aggregation ***********************************************************************
		c1 := make(map[lib.GroupingKey]lib.FilteredResponse)
		for _, v := range detResponses {
			lib.AddInMap(c1, v.DetTagGroupBy, v.Fr)
		}

		c3 := make(map[lib.GroupingKey]lib.FilteredResponse)
		for i, v := range c1 {
			lib.AddInMap(c3, i, v)
			lib.AddInMap(c3, i, v)
		}

		collAggrProof := lib.CollectiveAggregationProofCreation(c1, detResponses, c3)
		collAggrProofs := make([]lib.PublishedCollectiveAggregationProof, int(math.Log2(float64(sim.NbrServers))))
		for i := range collAggrProofs {
			collAggrProofs[i] = collAggrProof
		}
		root.ProtocolInstance().(*protocols.ProofsVerificationProtocol).TargetOfVerification = protocols.ProofsToVerify{KeySwitchingProofs: keySwitchingProofs,
			DeterministicTaggingProofs: deterministicTaggingProofs, DetTagAdditionProofs: deterministicTaggingAddProofs, AggregationProofs: aggregationProofs, ShufflingProofs: shufflingProofs, CollectiveAggregationProofs: collAggrProofs}

		round := lib.StartTimer("ProofsVerification(SIMULATION)")
		root.Start()
		results := <-root.ProtocolInstance().(*protocols.ProofsVerificationProtocol).FeedbackChannel
		log.LLvl1(len(results), " proofs verified")
		lib.EndTimer(round)
	}
	return nil
}
