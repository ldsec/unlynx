package protocols_test

import (
	"testing"
	"time"

	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/JoaoAndreSa/MedCo/protocols"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
)

func TestProofsVerification(t *testing.T) {
	local := onet.NewLocalTest()
	_, _, tree := local.GenTree(1, true)

	defer local.CloseAll()

	rootInstance, err := local.CreateProtocol("ProofsVerification", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}
	protocol := rootInstance.(*protocols.ProofsVerificationProtocol)

	secKey := network.Suite.Scalar().Pick(random.Stream)
	pubKey := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)

	secKeyNew := network.Suite.Scalar().Pick(random.Stream)
	pubKeyNew := network.Suite.Point().Mul(network.Suite.Point().Base(), secKeyNew)

	cipherOne := *lib.EncryptInt(pubKey, 10)

	cipherVect := lib.CipherVector{cipherOne, cipherOne}

	// key switching ***********************************************************************************************
	origEphemKeys := []abstract.Point{cipherOne.K, cipherOne.K}
	switchedVect, rs := lib.NewCipherVector(2).KeySwitching(cipherVect, origEphemKeys, pubKeyNew, secKey)
	cps := lib.VectorSwitchKeyProofCreation(cipherVect, *switchedVect, rs, secKey, origEphemKeys, pubKeyNew)
	pskp1 := lib.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKey, Q: pubKeyNew}

	cps = lib.VectorSwitchKeyProofCreation(cipherVect, *switchedVect, rs, secKey, []abstract.Point{cipherOne.K, cipherOne.K}, pubKey)
	pskp2 := lib.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKeyNew, Q: pubKeyNew}

	keySwitchingProofs := []lib.PublishedSwitchKeyProof{pskp1, pskp2}

	cipherOne1 := *lib.EncryptInt(pubKey, 10)
	cipherVect1 := lib.CipherVector{cipherOne1, cipherOne1}

	// deterministic tagging ***************************************************************************************
	tagSwitchedVect := lib.NewCipherVector(2).DeterministicTagging(&cipherVect1, secKey, secKeyNew)

	cps1 := lib.VectorDeterministicTagProofCreation(cipherVect1, *tagSwitchedVect, secKeyNew, secKey)
	pdhp1 := lib.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect1, VectAfter: *tagSwitchedVect, K: pubKey, SB: nil}

	cps1 = lib.VectorDeterministicTagProofCreation(cipherVect1, *tagSwitchedVect, secKeyNew, secKey)
	pdhp2 := lib.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect1, VectAfter: *tagSwitchedVect, K: pubKey, SB: network.Suite.Point().Mul(network.Suite.Point().Base(), secKeyNew)}

	cps1 = lib.VectorDeterministicTagProofCreation(cipherVect1, *tagSwitchedVect, secKey, secKey)
	pdhp3 := lib.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect1, VectAfter: *tagSwitchedVect, K: pubKey, SB: network.Suite.Point().Mul(network.Suite.Point().Base(), secKeyNew)}

	deterministicTaggingProofs := []lib.PublishedDeterministicTaggingProof{pdhp1, pdhp2, pdhp3}

	// deterministic tagging 2 *************************************************************************************
	tab := make([]int64, 2)
	for i := 0; i < len(tab); i++ {
		tab[i] = int64(1)
	}
	cipherVect = *lib.EncryptIntVector(pubKey, tab)
	var deterministicTaggingAddProofs []lib.PublishedDetTagAdditionProof
	toAdd := network.Suite.Point().Mul(network.Suite.Point().Base(), secKeyNew)
	toAddWrong := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)
	for j := 0; j < 2; j++ {
		for i := range cipherVect {
			tmp := network.Suite.Point()
			if j%2 == 0 {
				tmp = network.Suite.Point().Add(cipherVect[i].C, toAdd)
			} else {
				tmp = network.Suite.Point().Add(cipherVect[i].C, toAddWrong)
			}

			prf := lib.DetTagAdditionProofCreation(cipherVect[i].C, secKeyNew, toAdd, tmp)
			deterministicTaggingAddProofs = append(deterministicTaggingAddProofs, prf)
		}
	}

	// local aggregation *******************************************************************************************
	cipherOne2 := *lib.EncryptInt(pubKey, 10)
	cipherVect2 := lib.CipherVector{cipherOne2, cipherOne2}

	detResponses := make([]lib.FilteredResponseDet, 3)
	detResponses[0] = lib.FilteredResponseDet{Fr: lib.FilteredResponse{GroupByEnc: cipherVect2, AggregatingAttributes: cipherVect}, DetTagGroupBy: lib.CipherVectorToDeterministicTag(*switchedVect, secKey, secKey, pubKey, true)}
	detResponses[1] = lib.FilteredResponseDet{Fr: lib.FilteredResponse{GroupByEnc: cipherVect, AggregatingAttributes: cipherVect}, DetTagGroupBy: lib.CipherVectorToDeterministicTag(cipherVect2, secKey, secKey, pubKey, true)}
	detResponses[2] = lib.FilteredResponseDet{Fr: lib.FilteredResponse{GroupByEnc: cipherVect2, AggregatingAttributes: cipherVect}, DetTagGroupBy: lib.CipherVectorToDeterministicTag(*switchedVect, secKey, secKey, pubKey, true)}

	comparisonMap := make(map[lib.GroupingKey]lib.FilteredResponse)
	for _, v := range detResponses {
		lib.AddInMap(comparisonMap, v.DetTagGroupBy, v.Fr)
	}

	comparisonMap2 := make(map[lib.GroupingKey]lib.FilteredResponse)
	for i := 0; i < len(detResponses)-2; i++ {
		lib.AddInMap(comparisonMap2, detResponses[i].DetTagGroupBy, detResponses[i].Fr)
	}

	PublishedAggregationProof1 := lib.AggregationProofCreation(detResponses, comparisonMap)

	PublishedAggregationProof2 := lib.AggregationProofCreation(detResponses, comparisonMap2)

	aggregationProofs := []lib.PublishedAggregationProof{PublishedAggregationProof1, PublishedAggregationProof2}

	// shuffling ***************************************************************************************************
	clientResponsesToShuffle := make([]lib.ProcessResponse, 3)
	clientResponsesToShuffle[0] = lib.ProcessResponse{GroupByEnc: cipherVect2, WhereEnc: cipherVect2, AggregatingAttributes: cipherVect2}
	clientResponsesToShuffle[1] = lib.ProcessResponse{GroupByEnc: cipherVect1, WhereEnc: cipherVect1, AggregatingAttributes: cipherVect1}
	clientResponsesToShuffle[2] = lib.ProcessResponse{GroupByEnc: cipherVect2, WhereEnc: cipherVect2, AggregatingAttributes: cipherVect1}
	detResponsesCreationShuffled, pi, beta := lib.ShuffleSequence(clientResponsesToShuffle, nil, protocol.Roster().Aggregate, nil)

	PublishedShufflingProof1 := lib.ShufflingProofCreation(clientResponsesToShuffle, detResponsesCreationShuffled, nil, protocol.Roster().Aggregate, beta, pi)

	PublishedShufflingProof2 := lib.ShufflingProofCreation(clientResponsesToShuffle, clientResponsesToShuffle, nil, pubKey, beta, pi)

	shufflingProofs := []lib.PublishedShufflingProof{PublishedShufflingProof1, PublishedShufflingProof2}

	// collective aggregation **************************************************************************************
	c1 := make(map[lib.GroupingKey]lib.FilteredResponse)
	for _, v := range detResponses {
		lib.AddInMap(c1, v.DetTagGroupBy, v.Fr)
	}

	c3 := make(map[lib.GroupingKey]lib.FilteredResponse)
	for i, v := range c1 {
		lib.AddInMap(c3, i, v)
		lib.AddInMap(c3, i, v)
	}

	collectiveAggregationProof1 := lib.PublishedCollectiveAggregationProof{Aggregation1: c1, Aggregation2: detResponses, AggregationResults: c3}
	collectiveAggregationProof2 := lib.PublishedCollectiveAggregationProof{Aggregation1: c3, Aggregation2: detResponses, AggregationResults: c1}

	collectiveAggregationProofs := []lib.PublishedCollectiveAggregationProof{collectiveAggregationProof1, collectiveAggregationProof2}
	protocol.TargetOfVerification = protocols.ProofsToVerify{KeySwitchingProofs: keySwitchingProofs, DeterministicTaggingProofs: deterministicTaggingProofs, DetTagAdditionProofs: deterministicTaggingAddProofs, AggregationProofs: aggregationProofs, ShufflingProofs: shufflingProofs, CollectiveAggregationProofs: collectiveAggregationProofs}

	feedback := protocol.FeedbackChannel

	// keySwitchingProofs -> 2, deterministicTaggingProofs -> 3,deterministicTaggingAddProofs -> 4, aggregationProofs -> 2, shufflingProofs -> 2, collectiveAggregationProofs -> 2
	expRes := []bool{true, false, true, true, false, true, true, false, false, true, false, true, false, true, false}
	go protocol.Start()

	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond

	select {
	case results := <-feedback:
		assert.Equal(t, expRes, results)
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}
}
