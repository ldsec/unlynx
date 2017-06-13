package lib_test

import (
	"testing"
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

func TestShuffleSequence(t *testing.T) {
	// number of responses
	k := 10

	collectivePubKey, priv, _ := lib.GenKeys(k)
	collectivePrivKey := network.Suite.Scalar()

	for i := 0; i < len(priv); i++ {
		collectivePrivKey = network.Suite.Scalar().Add(collectivePrivKey, priv[i])
	}

	inputList := make([]lib.ProcessResponse, k)

	for i := 0; i < k; i++ {
		inputList[i] = lib.ProcessResponse{}

		for ii := range inputList[i].GroupByEnc {
			inputList[i].GroupByEnc[ii] = *lib.EncryptInt(collectivePubKey, int64(i+1))
		}
		for iii := range inputList[i].AggregatingAttributes {
			inputList[i].AggregatingAttributes[iii] = *lib.EncryptInt(collectivePubKey, int64(3*i+3))
		}

	}
	outputlist, pi, beta := lib.ShuffleSequence(inputList, nil, collectivePubKey, nil)

	//with proof
	shuffleProof := lib.ShufflingProofCreation(inputList, outputlist, nil, collectivePubKey, beta, pi)
	//shuffleProof = lib.ShufflingProofCreation(inputList, inputList, nil, collectivePubKey, beta, pi)
	log.Lvl1(lib.ShufflingProofVerification(shuffleProof, collectivePubKey))

	piinv := make([]int, k)
	for i := 0; i < k; i++ {
		piinv[pi[i]] = i
	}

	for i := 0; i < k; i++ {
		for iii := range inputList[0].GroupByEnc {
			decrypted := lib.DecryptInt(collectivePrivKey, outputlist[piinv[i]].GroupByEnc[iii])
			assert.Equal(t, int64(i+1), decrypted)
		}
		for iiii := range inputList[0].AggregatingAttributes {
			decrypted := lib.DecryptInt(collectivePrivKey, outputlist[piinv[i]].AggregatingAttributes[iiii])
			assert.Equal(t, int64(3*i+3), decrypted)
		}
	}

}
