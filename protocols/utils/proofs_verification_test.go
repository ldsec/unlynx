package protocolsunlynxutils_test

import (
	"testing"
	"time"

	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/network"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/proofs"
	"github.com/lca1/unlynx/protocols/utils"
	"github.com/stretchr/testify/assert"
)

func TestProofsVerification(t *testing.T) {
	local := onet.NewLocalTest(libunlynx.SuiTe)
	_, _, tree := local.GenTree(1, true)

	defer local.CloseAll()

	rootInstance, err := local.CreateProtocol("ProofsVerification", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}
	protocol := rootInstance.(*protocolsunlynxutils.ProofsVerificationProtocol)

	secKey := libunlynx.SuiTe.Scalar().Pick(libunlynx.SuiTe.RandomStream())
	pubKey := libunlynx.SuiTe.Point().Mul(secKey, libunlynx.SuiTe.Point().Base())

	secKeyNew := libunlynx.SuiTe.Scalar().Pick(libunlynx.SuiTe.RandomStream())
	pubKeyNew := libunlynx.SuiTe.Point().Mul(secKeyNew, libunlynx.SuiTe.Point().Base())

	cipherOne := *libunlynx.EncryptInt(pubKey, 10)

	cipherVect := libunlynx.CipherVector{cipherOne, cipherOne}

	// key switching ***********************************************************************************************
	origEphemKeys := []kyber.Point{cipherOne.K, cipherOne.K}
	switchedVect := libunlynx.NewCipherVector(2)
	rs := switchedVect.KeySwitching(cipherVect, origEphemKeys, pubKeyNew, secKey)
	cps := libunlynxproofs.VectorSwitchKeyProofCreation(cipherVect, *switchedVect, rs, secKey, origEphemKeys, pubKeyNew)
	pskp1 := libunlynxproofs.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKey, Q: pubKeyNew}

	cps = libunlynxproofs.VectorSwitchKeyProofCreation(cipherVect, *switchedVect, rs, secKey, []kyber.Point{cipherOne.K, cipherOne.K}, pubKey)
	pskp2 := libunlynxproofs.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKeyNew, Q: pubKeyNew}

	keySwitchingProofs := []libunlynxproofs.PublishedSwitchKeyProof{pskp1, pskp2}

	cipherOne1 := *libunlynx.EncryptInt(pubKey, 10)
	cipherVect1 := libunlynx.CipherVector{cipherOne1, cipherOne1}

	// deterministic tagging ***************************************************************************************
	tagSwitchedVect := libunlynx.NewCipherVector(2)
	tagSwitchedVect.DeterministicTagging(&cipherVect1, secKey, secKeyNew)

	cps1 := libunlynxproofs.VectorDeterministicTagProofCreation(cipherVect1, *tagSwitchedVect, secKeyNew, secKey)
	pdhp1 := libunlynxproofs.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect1, VectAfter: *tagSwitchedVect, K: pubKey, SB: nil}

	cps1 = libunlynxproofs.VectorDeterministicTagProofCreation(cipherVect1, *tagSwitchedVect, secKeyNew, secKey)
	pdhp2 := libunlynxproofs.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect1, VectAfter: *tagSwitchedVect, K: pubKey, SB: libunlynx.SuiTe.Point().Mul(secKeyNew, libunlynx.SuiTe.Point().Base())}

	cps1 = libunlynxproofs.VectorDeterministicTagProofCreation(cipherVect1, *tagSwitchedVect, secKey, secKey)
	pdhp3 := libunlynxproofs.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect1, VectAfter: *tagSwitchedVect, K: pubKey, SB: libunlynx.SuiTe.Point().Mul(secKeyNew, libunlynx.SuiTe.Point().Base())}

	deterministicTaggingProofs := []libunlynxproofs.PublishedDeterministicTaggingProof{pdhp1, pdhp2, pdhp3}

	// deterministic tagging 2 *************************************************************************************
	tab := make([]int64, 2)
	for i := 0; i < len(tab); i++ {
		tab[i] = int64(1)
	}
	cipherVect = *libunlynx.EncryptIntVector(pubKey, tab)
	var deterministicTaggingAddProofs []libunlynxproofs.PublishedDetTagAdditionProof
	toAdd := libunlynx.SuiTe.Point().Mul(secKeyNew, libunlynx.SuiTe.Point().Base())
	toAddWrong := libunlynx.SuiTe.Point().Mul(secKey, libunlynx.SuiTe.Point().Base())
	for j := 0; j < 2; j++ {
		for i := range cipherVect {
			tmp := libunlynx.SuiTe.Point()
			if j%2 == 0 {
				tmp = libunlynx.SuiTe.Point().Add(cipherVect[i].C, toAdd)
			} else {
				tmp = libunlynx.SuiTe.Point().Add(cipherVect[i].C, toAddWrong)
			}

			prf := libunlynxproofs.DetTagAdditionProofCreation(cipherVect[i].C, secKeyNew, toAdd, tmp)
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

	PublishedAggregationProof1 := libunlynxproofs.AggregationProofCreation(detResponses, comparisonMap)

	PublishedAggregationProof2 := libunlynxproofs.AggregationProofCreation(detResponses, comparisonMap2)

	aggregationProofs := []libunlynxproofs.PublishedAggregationProof{PublishedAggregationProof1, PublishedAggregationProof2}

	// shuffling ***************************************************************************************************
	cipherVectorToShuffle := make([]libunlynx.CipherVector, 3)
	cipherVectorToShuffle[0] = append(append(cipherVect2, cipherVect2...), cipherVect2...)
	cipherVectorToShuffle[1] = append(append(cipherVect1, cipherVect1...), cipherVect1...)
	cipherVectorToShuffle[2] = append(append(cipherVect2, cipherVect2...), cipherVect1...)
	detResponsesCreationShuffled, pi, beta := libunlynx.ShuffleSequence(cipherVectorToShuffle, nil, protocol.Roster().Aggregate, nil)

	PublishedShufflingProof1 := libunlynxproofs.ShufflingProofCreation(cipherVectorToShuffle, detResponsesCreationShuffled, nil, protocol.Roster().Aggregate, beta, pi)

	PublishedShufflingProof2 := libunlynxproofs.ShufflingProofCreation(cipherVectorToShuffle, cipherVectorToShuffle, nil, pubKey, beta, pi)

	shufflingProofs := []libunlynxproofs.PublishedShufflingProof{PublishedShufflingProof1, PublishedShufflingProof2}

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

	collectiveAggregationProof1 := libunlynxproofs.PublishedCollectiveAggregationProof{Aggregation1: c1, Aggregation2: detResponses, AggregationResults: c3}
	collectiveAggregationProof2 := libunlynxproofs.PublishedCollectiveAggregationProof{Aggregation1: c3, Aggregation2: detResponses, AggregationResults: c1}

	collectiveAggregationProofs := []libunlynxproofs.PublishedCollectiveAggregationProof{collectiveAggregationProof1, collectiveAggregationProof2}
	protocol.TargetOfVerification = protocolsunlynxutils.ProofsToVerify{KeySwitchingProofs: keySwitchingProofs, DeterministicTaggingProofs: deterministicTaggingProofs, DetTagAdditionProofs: deterministicTaggingAddProofs, AggregationProofs: aggregationProofs, ShufflingProofs: shufflingProofs, CollectiveAggregationProofs: collectiveAggregationProofs}

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
