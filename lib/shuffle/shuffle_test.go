package libunlynxshuffle_test

import (
	"os"
	"testing"

	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/proofs"
	. "github.com/lca1/unlynx/lib/shuffle"
	"github.com/stretchr/testify/assert"
)

func TestShuffleSequence(t *testing.T) {
	// number of responses
	k := 10

	collectivePubKey, priv, _ := libunlynx.GenKeys(k)
	collectivePrivKey := libunlynx.SuiTe.Scalar()

	for i := 0; i < len(priv); i++ {
		collectivePrivKey = libunlynx.SuiTe.Scalar().Add(collectivePrivKey, priv[i])
	}

	inputList := make([]libunlynx.CipherVector, k)

	for i := 0; i < k; i++ {
		inputList[i] = make(libunlynx.CipherVector, k)

		for ii := range inputList[i] {
			inputList[i][ii] = *libunlynx.EncryptInt(collectivePubKey, int64(i+1))
		}

	}
	outputlist, pi, beta := ShuffleSequence(inputList, libunlynx.SuiTe.Point().Base(), collectivePubKey, nil)

	//with proof
	shuffleProof := libunlynxproofs.ShufflingProofCreation(inputList, outputlist, libunlynx.SuiTe.Point().Base(), collectivePubKey, beta, pi)
	log.Lvl1(libunlynxproofs.ShufflingProofVerification(shuffleProof, collectivePubKey))

	piinv := make([]int, k)
	for i := 0; i < k; i++ {
		piinv[pi[i]] = i
	}

	for i := 0; i < k; i++ {
		for iii := range inputList[0] {
			decrypted := libunlynx.DecryptInt(collectivePrivKey, outputlist[piinv[i]][iii])
			assert.Equal(t, int64(i+1), decrypted)
		}
	}

}

func TestPrecomputationWritingForShuffling(t *testing.T) {
	os.Remove("pre_compute_multiplications.gob")
	local := onet.NewLocalTest(libunlynx.SuiTe)
	_, el, _ := local.GenTree(3, true)
	defer local.CloseAll()

	lineSize := 10
	secret := libunlynx.SuiTe.Scalar().Pick(random.New())

	precompute := PrecomputationWritingForShuffling(false, "pre_compute_multiplications.gob", "test_server", secret, el.Aggregate, lineSize)
	assert.Equal(t, len(precompute), lineSize)

	// writes precomputation file
	precompute = PrecomputationWritingForShuffling(true, "pre_compute_multiplications.gob", "test_server", secret, el.Aggregate, lineSize)
	assert.Equal(t, len(precompute), lineSize)

	// reads precomputation file
	precompute = ReadPrecomputedFile("pre_compute_multiplications.gob")
	assert.Equal(t, len(precompute), lineSize)

}
