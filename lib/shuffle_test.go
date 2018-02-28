package libunlynx_test

import (
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestShuffleSequence(t *testing.T) {
	// number of responses
	k := 10

	collectivePubKey, priv, _ := libunlynx.GenKeys(k)
	collectivePrivKey := libunlynx.SuiteT.Scalar()

	for i := 0; i < len(priv); i++ {
		collectivePrivKey = libunlynx.SuiteT.Scalar().Add(collectivePrivKey, priv[i])
	}

	inputList := make([]libunlynx.ProcessResponse, k)

	for i := 0; i < k; i++ {
		inputList[i] = libunlynx.ProcessResponse{}

		for ii := range inputList[i].GroupByEnc {
			inputList[i].GroupByEnc[ii] = *libunlynx.EncryptInt(collectivePubKey, int64(i+1))
		}
		for iii := range inputList[i].AggregatingAttributes {
			inputList[i].AggregatingAttributes[iii] = *libunlynx.EncryptInt(collectivePubKey, int64(3*i+3))
		}

	}
	outputlist, pi, beta := libunlynx.ShuffleSequence(inputList, nil, collectivePubKey, nil)

	//with proof
	shuffleProof := libunlynx.ShufflingProofCreation(inputList, outputlist, nil, collectivePubKey, beta, pi)
	//shuffleProof = lib.ShufflingProofCreation(inputList, inputList, nil, collectivePubKey, beta, pi)
	log.Lvl1(libunlynx.ShufflingProofVerification(shuffleProof, collectivePubKey))

	piinv := make([]int, k)
	for i := 0; i < k; i++ {
		piinv[pi[i]] = i
	}

	for i := 0; i < k; i++ {
		for iii := range inputList[0].GroupByEnc {
			decrypted := libunlynx.DecryptInt(collectivePrivKey, outputlist[piinv[i]].GroupByEnc[iii])
			assert.Equal(t, int64(i+1), decrypted)
		}
		for iiii := range inputList[0].AggregatingAttributes {
			decrypted := libunlynx.DecryptInt(collectivePrivKey, outputlist[piinv[i]].AggregatingAttributes[iiii])
			assert.Equal(t, int64(3*i+3), decrypted)
		}
	}

}

func TestPrecomputationWritingForShuffling(t *testing.T) {
	os.Remove("pre_compute_multiplications.gob")
	local := onet.NewLocalTest(libunlynx.SuiteT)
	_, el, _ := local.GenTree(3, true)
	defer local.CloseAll()

	lineSize := 10
	secret := libunlynx.SuiteT.Scalar().Pick(random.New())

	precompute := libunlynx.PrecomputationWritingForShuffling(false, "pre_compute_multiplications.gob", "test_server", secret, el.Aggregate, lineSize)
	assert.Equal(t, len(precompute), lineSize)

	// writes precomputation file
	precompute = libunlynx.PrecomputationWritingForShuffling(true, "pre_compute_multiplications.gob", "test_server", secret, el.Aggregate, lineSize)
	assert.Equal(t, len(precompute), lineSize)

	// reads precomputation file
	precompute = libunlynx.ReadPrecomputedFile("pre_compute_multiplications.gob")
	assert.Equal(t, len(precompute), lineSize)

}
