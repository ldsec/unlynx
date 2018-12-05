package libunlynxproofs_test

import (
	"testing"

	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/proofs"
	"github.com/lca1/unlynx/lib/shuffle"
	"github.com/stretchr/testify/assert"
)

func TestPublishedShufflingProof_ToBytes(t *testing.T) {
	psp := libunlynxproofs.PublishedShufflingProof{}

	tab := []int64{1, 2, 3, 6}
	testOriginalList := make([]libunlynx.CipherVector, 0)
	testOriginalList = append(testOriginalList, *libunlynx.EncryptIntVector(pubKey, tab))
	psp.OriginalList = testOriginalList

	testShuffledList := make([]libunlynx.CipherVector, 0)
	testShuffledList = append(testShuffledList, *libunlynx.EncryptIntVector(pubKey, tab))
	psp.ShuffledList = testShuffledList

	psp.G = pubKey
	psp.H = pubKey

	tabInt := []int{1, 2, 3, 6}
	psp.HashProof = libunlynx.UnsafeCastIntsToBytes(tabInt)

	pspb := psp.ToBytes()

	converted := libunlynxproofs.PublishedShufflingProof{}
	converted.FromBytes(pspb)

	assert.Equal(t, tab, libunlynx.DecryptIntVector(secKey, &converted.OriginalList[0]))
	assert.Equal(t, tab, libunlynx.DecryptIntVector(secKey, &converted.ShuffledList[0]))
	assert.Equal(t, psp.HashProof, converted.HashProof)
	assert.True(t, psp.G.Equal(converted.G))
	assert.True(t, psp.H.Equal(converted.H))
}

func TestShufflingProof(t *testing.T) {
	tab1 := []int64{1, 2, 3, 6}
	testCipherVect1 := *libunlynx.EncryptIntVector(pubKey, tab1)

	tab2 := []int64{2, 4, 8, 6}
	testCipherVect2 := *libunlynx.EncryptIntVector(pubKey, tab2)

	responses := make([]libunlynx.CipherVector, 3)
	responses[0] = append(testCipherVect2, testCipherVect2...)
	responses[1] = append(testCipherVect1, testCipherVect1...)
	responses[2] = append(testCipherVect2, testCipherVect1...)

	responsesShuffled, pi, beta := libunlynxshuffle.ShuffleSequence(responses, libunlynx.SuiTe.Point().Base(), pubKey, nil)
	PublishedShufflingProof := libunlynxproofs.ShufflingProofCreation(responses, responsesShuffled, libunlynx.SuiTe.Point().Base(), pubKey, beta, pi)
	assert.True(t, libunlynxproofs.ShufflingProofVerification(PublishedShufflingProof, pubKey))

	PublishedShufflingProof = libunlynxproofs.ShufflingProofCreation(responses, responses, libunlynx.SuiTe.Point().Base(), pubKey, beta, pi)
	assert.False(t, libunlynxproofs.ShufflingProofVerification(PublishedShufflingProof, pubKey))
}
