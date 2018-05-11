package libunlynxproofs_test

import (
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/proofs"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestShufflingProof(t *testing.T) {
	tab1 := []int64{1, 2, 3, 6}
	testCipherVect1 := *libunlynx.EncryptIntVector(pubKey, tab1)

	tab2 := []int64{2, 4, 8, 6}
	testCipherVect2 := *libunlynx.EncryptIntVector(pubKey, tab2)

	responses := make([]libunlynx.CipherVector, 3)
	responses[0] = append(testCipherVect2, testCipherVect2...)
	responses[1] = append(testCipherVect1, testCipherVect1...)
	responses[2] = append(testCipherVect2, testCipherVect1...)

	responsesShuffled, pi, beta := libunlynx.ShuffleSequence(responses, nil, pubKey, nil)
	PublishedShufflingProof := libunlynxproofs.ShufflingProofCreation(responses, responsesShuffled, nil, pubKey, beta, pi)
	assert.True(t, libunlynxproofs.ShufflingProofVerification(PublishedShufflingProof, pubKey))

	PublishedShufflingProof = libunlynxproofs.ShufflingProofCreation(responses, responses, nil, pubKey, beta, pi)
	assert.False(t, libunlynxproofs.ShufflingProofVerification(PublishedShufflingProof, pubKey))
}
