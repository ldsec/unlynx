package protocolsunlynxutils_test

import (
	"testing"
	"time"

	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/aggregation"
	"github.com/lca1/unlynx/lib/deterministic_tag"
	"github.com/lca1/unlynx/lib/key_switch"
	"github.com/lca1/unlynx/lib/shuffle"
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

	// key switching ***************************************************************************************************
	origEphemKeys := []kyber.Point{cipherOne.K, cipherOne.K}

	_, ks2s, rBNegs, vis := libunlynxkeyswitch.KeySwitchSequence(pubKeyNew, origEphemKeys, secKey)
	pskp := libunlynxkeyswitch.KeySwitchListProofCreation(pubKey, pubKeyNew, secKey, ks2s, rBNegs, vis)
	keySwitchingProofs := pskp

	// deterministic tagging (creation) ********************************************************************************
	cipherOne1 := *libunlynx.EncryptInt(pubKey, 10)
	cipherVect1 := libunlynx.CipherVector{cipherOne1, cipherOne1}

	tagSwitchedVect := libunlynxdetertag.DeterministicTagSequence(cipherVect1, secKey, secKeyNew)

	cps := libunlynxdetertag.DeterministicTagCrListProofCreation(cipherVect1, tagSwitchedVect, pubKey, secKey, secKeyNew)
	deterministicTaggingCrProofs := cps

	// deterministic tagging (addition) ********************************************************************************

	tab := []int64{int64(1), int64(1)}
	cipherVect = *libunlynx.EncryptIntVector(pubKey, tab)

	deterministicTaggingAddProofs := libunlynxdetertag.PublishedDDTAdditionListProof{}
	deterministicTaggingAddProofs.List = make([]libunlynxdetertag.PublishedDDTAdditionProof, 0)

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

			prf := libunlynxdetertag.DeterministicTagAdditionProofCreation(cipherVect[i].C, secKeyNew, toAdd, tmp)
			deterministicTaggingAddProofs.List = append(deterministicTaggingAddProofs.List, prf)
		}
	}

	// local aggregation ***********************************************************************************************
	cipherOne2 := *libunlynx.EncryptInt(pubKey, 10)
	cipherVect2 := libunlynx.CipherVector{cipherOne2, cipherOne2}

	res := cipherVect2.Acum()

	prfAggregation1 := libunlynxaggr.AggregationProofCreation(cipherVect2, res)
	prfAggregation2 := libunlynxaggr.AggregationProofCreation(cipherVect2, cipherVect2[0])

	aggregationProofs := libunlynxaggr.PublishedAggregationListProof{}
	aggregationProofs.List = append(aggregationProofs.List, prfAggregation1, prfAggregation2)

	// shuffling *******************************************************************************************************
	cipherVectorToShuffle := make([]libunlynx.CipherVector, 3)
	cipherVectorToShuffle[0] = append(append(cipherVect2, cipherVect2...), cipherVect2...)
	cipherVectorToShuffle[1] = append(append(cipherVect1, cipherVect1...), cipherVect1...)
	cipherVectorToShuffle[2] = append(append(cipherVect2, cipherVect2...), cipherVect1...)
	detResponsesCreationShuffled, pi, beta := libunlynxshuffle.ShuffleSequence(cipherVectorToShuffle, libunlynx.SuiTe.Point().Base(), protocol.Roster().Aggregate, nil)

	prfShuffling1 := libunlynxshuffle.ShuffleProofCreation(cipherVectorToShuffle, detResponsesCreationShuffled, libunlynx.SuiTe.Point().Base(), protocol.Roster().Aggregate, beta, pi)
	prfShuffling2 := libunlynxshuffle.ShuffleProofCreation(cipherVectorToShuffle, cipherVectorToShuffle, libunlynx.SuiTe.Point().Base(), pubKey, beta, pi)

	shufflingProofs := libunlynxshuffle.PublishedShufflingListProof{}
	shufflingProofs.List = append(shufflingProofs.List, prfShuffling1, prfShuffling2)

	// add data to protocol *******************************************************************************************

	protocol.TargetOfVerification = protocolsunlynxutils.ProofsToVerify{
		KeySwitchingProofs:          keySwitchingProofs,
		DetTagCreationProofs:        deterministicTaggingCrProofs,
		DetTagAdditionProofs:        deterministicTaggingAddProofs,
		AggregationProofs:           aggregationProofs,
		ShufflingProofs:             shufflingProofs,
		CollectiveAggregationProofs: aggregationProofs,
	}
	feedback := protocol.FeedbackChannel

	expRes := []bool{true, true, false, false, false, false}
	go func() {
		if err := protocol.Start(); err != nil {
			log.Fatal("Error to Start <ProofsVerification> protocol:", err)
		}
	}()

	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*10) * time.Millisecond

	select {
	case results := <-feedback:
		assert.Equal(t, expRes, results)
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}
}
