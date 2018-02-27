package protocolsunlynx_test

import (
	"testing"
	"time"

	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/protocols"
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
	protocol := rootInstance.(*protocolsunlynx.ProofsVerificationProtocol)

	secKey := network.Suite.Scalar().Pick(random.Stream)
	pubKey := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)

	secKeyNew := network.Suite.Scalar().Pick(random.Stream)
	pubKeyNew := network.Suite.Point().Mul(network.Suite.Point().Base(), secKeyNew)

	cipherOne := *libunlynx.EncryptInt(pubKey, 10)

	cipherVect := libunlynx.CipherVector{cipherOne, cipherOne}

	// key switching ***********************************************************************************************
	origEphemKeys := []abstract.Point{cipherOne.K, cipherOne.K}
	switchedVect := libunlynx.NewCipherVector(2)
	rs := switchedVect.KeySwitching(cipherVect, origEphemKeys, pubKeyNew, secKey)
	cps := libunlynx.VectorSwitchKeyProofCreation(cipherVect, *switchedVect, rs, secKey, origEphemKeys, pubKeyNew)
	pskp1 := libunlynx.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKey, Q: pubKeyNew}

	cps = libunlynx.VectorSwitchKeyProofCreation(cipherVect, *switchedVect, rs, secKey, []abstract.Point{cipherOne.K, cipherOne.K}, pubKey)
	pskp2 := libunlynx.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKeyNew, Q: pubKeyNew}

	keySwitchingProofs := []libunlynx.PublishedSwitchKeyProof{pskp1, pskp2}

	cipherOne1 := *libunlynx.EncryptInt(pubKey, 10)
	cipherVect1 := libunlynx.CipherVector{cipherOne1, cipherOne1}

	// deterministic tagging ***************************************************************************************
	tagSwitchedVect := libunlynx.NewCipherVector(2)
	tagSwitchedVect.DeterministicTagging(&cipherVect1, secKey, secKeyNew)

	cps1 := libunlynx.VectorDeterministicTagProofCreation(cipherVect1, *tagSwitchedVect, secKeyNew, secKey)
	pdhp1 := libunlynx.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect1, VectAfter: *tagSwitchedVect, K: pubKey, SB: nil}

	cps1 = libunlynx.VectorDeterministicTagProofCreation(cipherVect1, *tagSwitchedVect, secKeyNew, secKey)
	pdhp2 := libunlynx.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect1, VectAfter: *tagSwitchedVect, K: pubKey, SB: network.Suite.Point().Mul(network.Suite.Point().Base(), secKeyNew)}

	cps1 = libunlynx.VectorDeterministicTagProofCreation(cipherVect1, *tagSwitchedVect, secKey, secKey)
	pdhp3 := libunlynx.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect1, VectAfter: *tagSwitchedVect, K: pubKey, SB: network.Suite.Point().Mul(network.Suite.Point().Base(), secKeyNew)}

	deterministicTaggingProofs := []libunlynx.PublishedDeterministicTaggingProof{pdhp1, pdhp2, pdhp3}

	// deterministic tagging 2 *************************************************************************************
	tab := make([]int64, 2)
	for i := 0; i < len(tab); i++ {
		tab[i] = int64(1)
	}
	cipherVect = *libunlynx.EncryptIntVector(pubKey, tab)
	var deterministicTaggingAddProofs []libunlynx.PublishedDetTagAdditionProof
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

			prf := libunlynx.DetTagAdditionProofCreation(cipherVect[i].C, secKeyNew, toAdd, tmp)
			deterministicTaggingAddProofs = append(deterministicTaggingAddProofs, prf)
		}
	}

	// local aggregation *******************************************************************************************
	cipherOne2 := *libunlynx.EncryptInt(pubKey, 10)
	cipherVect2 := libunlynx.CipherVector{cipherOne2, cipherOne2}

	detResponses := make([]libunlynx.FilteredResponseDet, 3)
	detResponses[0] = libunlynx.FilteredResponseDet{Fr: libunlynx.FilteredResponse{GroupByEnc: cipherVect2, AggregatingAttributes: cipherVect}, DetTagGroupBy: libunlynx.CipherVectorToDeterministicTag(*switchedVect, secKey, secKey, pubKey, true)}
	detResponses[1] = libunlynx.FilteredResponseDet{Fr: libunlynx.FilteredResponse{GroupByEnc: cipherVect, AggregatingAttributes: cipherVect}, DetTagGroupBy: libunlynx.CipherVectorToDeterministicTag(cipherVect2, secKey, secKey, pubKey, true)}
	detResponses[2] = libunlynx.FilteredResponseDet{Fr: libunlynx.FilteredResponse{GroupByEnc: cipherVect2, AggregatingAttributes: cipherVect}, DetTagGroupBy: libunlynx.CipherVectorToDeterministicTag(*switchedVect, secKey, secKey, pubKey, true)}

	comparisonMap := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)
	for _, v := range detResponses {
		libunlynx.AddInMap(comparisonMap, v.DetTagGroupBy, v.Fr)
	}

	comparisonMap2 := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)
	for i := 0; i < len(detResponses)-2; i++ {
		libunlynx.AddInMap(comparisonMap2, detResponses[i].DetTagGroupBy, detResponses[i].Fr)
	}

	PublishedAggregationProof1 := libunlynx.AggregationProofCreation(detResponses, comparisonMap)

	PublishedAggregationProof2 := libunlynx.AggregationProofCreation(detResponses, comparisonMap2)

	aggregationProofs := []libunlynx.PublishedAggregationProof{PublishedAggregationProof1, PublishedAggregationProof2}

	// shuffling ***************************************************************************************************
	processResponsesToShuffle := make([]libunlynx.ProcessResponse, 3)
	processResponsesToShuffle[0] = libunlynx.ProcessResponse{GroupByEnc: cipherVect2, WhereEnc: cipherVect2, AggregatingAttributes: cipherVect2}
	processResponsesToShuffle[1] = libunlynx.ProcessResponse{GroupByEnc: cipherVect1, WhereEnc: cipherVect1, AggregatingAttributes: cipherVect1}
	processResponsesToShuffle[2] = libunlynx.ProcessResponse{GroupByEnc: cipherVect2, WhereEnc: cipherVect2, AggregatingAttributes: cipherVect1}
	detResponsesCreationShuffled, pi, beta := libunlynx.ShuffleSequence(processResponsesToShuffle, nil, protocol.Roster().Aggregate, nil)

	PublishedShufflingProof1 := libunlynx.ShufflingProofCreation(processResponsesToShuffle, detResponsesCreationShuffled, nil, protocol.Roster().Aggregate, beta, pi)

	PublishedShufflingProof2 := libunlynx.ShufflingProofCreation(processResponsesToShuffle, processResponsesToShuffle, nil, pubKey, beta, pi)

	shufflingProofs := []libunlynx.PublishedShufflingProof{PublishedShufflingProof1, PublishedShufflingProof2}

	// collective aggregation **************************************************************************************
	c1 := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)
	for _, v := range detResponses {
		libunlynx.AddInMap(c1, v.DetTagGroupBy, v.Fr)
	}

	c3 := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)
	for i, v := range c1 {
		libunlynx.AddInMap(c3, i, v)
		libunlynx.AddInMap(c3, i, v)
	}

	collectiveAggregationProof1 := libunlynx.PublishedCollectiveAggregationProof{Aggregation1: c1, Aggregation2: detResponses, AggregationResults: c3}
	collectiveAggregationProof2 := libunlynx.PublishedCollectiveAggregationProof{Aggregation1: c3, Aggregation2: detResponses, AggregationResults: c1}

	collectiveAggregationProofs := []libunlynx.PublishedCollectiveAggregationProof{collectiveAggregationProof1, collectiveAggregationProof2}
	protocol.TargetOfVerification = protocolsunlynx.ProofsToVerify{KeySwitchingProofs: keySwitchingProofs, DeterministicTaggingProofs: deterministicTaggingProofs, DetTagAdditionProofs: deterministicTaggingAddProofs, AggregationProofs: aggregationProofs, ShufflingProofs: shufflingProofs, CollectiveAggregationProofs: collectiveAggregationProofs}

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
