package main

import (
	"github.com/BurntSushi/toml"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/proofs"
	"github.com/lca1/unlynx/protocols/utils"
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
	log.Lvl1("Setup done")
	return sc, nil
}

// Run starts the simulation.
func (sim *ProofsVerificationSimulation) Run(config *onet.SimulationConfig) error {

	for round := 0; round < sim.Rounds; round++ {
		log.Lvl1("Starting round", round)
		rooti, err := config.Overlay.CreateProtocol("ProofsVerification", config.Tree, onet.NilServiceID)
		if err != nil {
			return err
		}

		root := rooti.(*protocolsunlynxutils.ProofsVerificationProtocol)
		secKey := libunlynx.SuiTe.Scalar().Pick(random.New())
		pubKey := libunlynx.SuiTe.Point().Mul(secKey, libunlynx.SuiTe.Point().Base())
		secKeyNew := libunlynx.SuiTe.Scalar().Pick(random.New())
		pubKeyNew := libunlynx.SuiTe.Point().Mul(secKeyNew, libunlynx.SuiTe.Point().Base())
		tab := make([]int64, sim.NbrAggrAttributes+sim.NbrGroupAttributes)

		// key switching **********************************************************
		for i := 0; i < len(tab); i++ {
			tab[i] = int64(1)
		}
		cipherVect := *libunlynx.EncryptIntVector(pubKey, tab)

		origEphemKeys := make([]kyber.Point, len(cipherVect))
		origCipherVector := *libunlynx.NewCipherVector(len(cipherVect))
		for i, v := range cipherVect {
			origEphemKeys[i] = v.K
			origCipherVector[i].C = v.C
		}

		switchedVect := libunlynx.NewCipherVector(len(cipherVect))
		rs := switchedVect.KeySwitching(cipherVect, origEphemKeys, pubKeyNew, secKey)
		cps := libunlynxproofs.VectorSwitchKeyProofCreation(cipherVect, *switchedVect, rs, secKey, origEphemKeys, pubKeyNew)
		pskp := libunlynxproofs.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKey, Q: pubKeyNew}
		keySwitchingProofs := make([]libunlynxproofs.PublishedSwitchKeyProof, sim.NbrGroups)

		for i := range keySwitchingProofs {
			keySwitchingProofs[i] = pskp
		}

		// deterministic tagging ************************************************************
		tab = make([]int64, sim.NbrGroupAttributes)
		for i := 0; i < len(tab); i++ {
			tab[i] = int64(1)
		}
		cipherVect = *libunlynx.EncryptIntVector(pubKey, tab)

		tagSwitchedVect := libunlynx.NewCipherVector(len(cipherVect))
		tagSwitchedVect.DeterministicTagging(&cipherVect, secKey, secKeyNew)
		cps1 := libunlynxproofs.VectorDeterministicTagProofCreation(cipherVect, *tagSwitchedVect, secKeyNew, secKey)
		newContrib := libunlynx.SuiTe.Point().Mul(secKeyNew, libunlynx.SuiTe.Point().Base())
		pdhp := libunlynxproofs.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *tagSwitchedVect, K: pubKey, SB: newContrib}
		deterministicTaggingProofs := make([]libunlynxproofs.PublishedDeterministicTaggingProof, sim.NbrResponses*sim.NbrServers)

		for i := range deterministicTaggingProofs {
			deterministicTaggingProofs[i] = pdhp
		}

		// deterministic tagging 2 ************************************************************
		tab = make([]int64, sim.NbrGroupAttributes)
		for i := 0; i < len(tab); i++ {
			tab[i] = int64(1)
		}
		cipherVect = *libunlynx.EncryptIntVector(pubKey, tab)

		var deterministicTaggingAddProofs []libunlynxproofs.PublishedDetTagAdditionProof
		toAdd := libunlynx.SuiTe.Point().Mul(secKeyNew, libunlynx.SuiTe.Point().Base())

		for i := range cipherVect {
			tmp := libunlynx.SuiTe.Point().Add(cipherVect[i].C, toAdd)
			prf := libunlynxproofs.DetTagAdditionProofCreation(cipherVect[i].C, secKeyNew, toAdd, tmp)
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
		cipherVect = *libunlynx.EncryptIntVector(pubKey, tab)

		tab1 := make([]int64, sim.NbrGroupAttributes)
		for i := 0; i < len(tab1); i++ {
			tab1[i] = int64(1)
		}
		cipherVectGr := *libunlynx.EncryptIntVector(pubKey, tab1)
		testCipherVect1 := *libunlynx.EncryptIntVector(pubKey, tab)

		detResponses := make([]libunlynx.FilteredResponseDet, 0)
		for i := 0; i < sim.NbrGroups; i++ {
			tmp := libunlynx.NewCipherVector(sim.NbrGroupAttributes)
			tmp.Add(cipherVectGr, cipherVectGr)

			cipherVectGr = *tmp
			det1 := cipherVectGr
			det1.TaggingDet(secKey, secKey, pubKey, false)
			deterministicGroupAttributes := make(libunlynx.DeterministCipherVector, len(det1))

			for j, c := range det1 {
				deterministicGroupAttributes[j] = libunlynx.DeterministCipherText{Point: c.C}
			}

			newDetResponse := libunlynx.FilteredResponseDet{Fr: libunlynx.FilteredResponse{GroupByEnc: cipherVectGr, AggregatingAttributes: testCipherVect1}, DetTagGroupBy: deterministicGroupAttributes.Key()}
			for j := 0; j < (sim.NbrResponses/sim.NbrServers)/sim.NbrGroups; j++ {
				detResponses = append(detResponses, newDetResponse)
			}
		}

		comparisonMap := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)
		for _, v := range detResponses {
			libunlynx.AddInMap(comparisonMap, v.DetTagGroupBy, v.Fr)
		}

		PublishedAggregationProof := libunlynxproofs.AggregationProofCreation(detResponses, comparisonMap)
		aggregationProofs := make([]libunlynxproofs.PublishedAggregationProof, sim.NbrServers)
		for i := range aggregationProofs {
			aggregationProofs[i] = PublishedAggregationProof
		}

		//shuffling *****************************************************************************

		log.Lvl1("Starting shuffling (can take some time)")
		responsesToShuffle := make([]libunlynx.ProcessResponse, sim.NbrResponses/sim.NbrServers)
		for i := 0; i < sim.NbrResponses/sim.NbrServers; i++ {
			responsesToShuffle[i] = libunlynx.ProcessResponse{GroupByEnc: cipherVectGr, AggregatingAttributes: testCipherVect1}
		}

		clientResponsesShuffled, pi, beta := libunlynx.ShuffleSequence(responsesToShuffle, nil, root.Roster().Aggregate, nil)
		log.Lvl1("Starting shuffling proof creation")
		shufflingProof := libunlynxproofs.ShufflingProofCreation(responsesToShuffle, clientResponsesShuffled, nil, root.Roster().Aggregate, beta, pi)
		shufflingProofs := make([]libunlynxproofs.PublishedShufflingProof, sim.NbrServers*sim.NbrServers)
		for i := range shufflingProofs {
			shufflingProofs[i] = shufflingProof
		}

		//collective aggregation ***********************************************************************
		c1 := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)
		for _, v := range detResponses {
			libunlynx.AddInMap(c1, v.DetTagGroupBy, v.Fr)
		}

		c3 := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)
		for i, v := range c1 {
			libunlynx.AddInMap(c3, i, v)
			libunlynx.AddInMap(c3, i, v)
		}

		collAggrProof := libunlynxproofs.CollectiveAggregationProofCreation(c1, detResponses, c3)
		collAggrProofs := make([]libunlynxproofs.PublishedCollectiveAggregationProof, int(math.Log2(float64(sim.NbrServers))))
		for i := range collAggrProofs {
			collAggrProofs[i] = collAggrProof
		}
		root.ProtocolInstance().(*protocolsunlynxutils.ProofsVerificationProtocol).TargetOfVerification = protocolsunlynxutils.ProofsToVerify{KeySwitchingProofs: keySwitchingProofs,
			DeterministicTaggingProofs: deterministicTaggingProofs, DetTagAdditionProofs: deterministicTaggingAddProofs, AggregationProofs: aggregationProofs, ShufflingProofs: shufflingProofs, CollectiveAggregationProofs: collAggrProofs}

		round := libunlynx.StartTimer("ProofsVerification(SIMULATION)")
		root.Start()
		results := <-root.ProtocolInstance().(*protocolsunlynxutils.ProofsVerificationProtocol).FeedbackChannel
		log.Lvl1(len(results), " proofs verified")
		libunlynx.EndTimer(round)
	}
	return nil
}
