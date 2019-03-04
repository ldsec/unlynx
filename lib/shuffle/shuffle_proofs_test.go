package libunlynxshuffle_test

//import (
//	"testing"
//
//	"github.com/dedis/kyber/util/key"
//
//	"github.com/lca1/unlynx/lib"
//	"github.com/lca1/unlynx/lib/shuffle"
//	"github.com/stretchr/testify/assert"
//)
//
//func TestPublishedShufflingProof_ToBytes(t *testing.T) {
//	keys := key.NewKeyPair(libunlynx.SuiTe)
//
//	psp := libunlynxshuffle.PublishedShufflingProof{}
//
//	tab := []int64{1, 2, 3, 6}
//	testOriginalList := make([]libunlynx.CipherVector, 0)
//	testOriginalList = append(testOriginalList, *libunlynx.EncryptIntVector(keys.Public, tab))
//	psp.OriginalList = testOriginalList
//
//	testShuffledList := make([]libunlynx.CipherVector, 0)
//	testShuffledList = append(testShuffledList, *libunlynx.EncryptIntVector(keys.Public, tab))
//	psp.ShuffledList = testShuffledList
//
//	psp.G = keys.Public
//	psp.H = keys.Public
//
//	tabInt := []int{1, 2, 3, 6}
//	psp.HashProof = libunlynx.UnsafeCastIntsToBytes(tabInt)
//
//	pspb := psp.ToBytes()
//
//	converted := libunlynxshuffle.PublishedShufflingProof{}
//	converted.FromBytes(pspb)
//
//	assert.Equal(t, tab, libunlynx.DecryptIntVector(keys.Private, &converted.OriginalList[0]))
//	assert.Equal(t, tab, libunlynx.DecryptIntVector(keys.Private, &converted.ShuffledList[0]))
//	assert.Equal(t, psp.HashProof, converted.HashProof)
//	assert.True(t, psp.G.Equal(converted.G))
//	assert.True(t, psp.H.Equal(converted.H))
//}
//
//func TestShufflingProof(t *testing.T) {
//	keys := key.NewKeyPair(libunlynx.SuiTe)
//
//	tab1 := []int64{1, 2, 3, 6}
//	testCipherVect1 := *libunlynx.EncryptIntVector(keys.Public, tab1)
//
//	tab2 := []int64{2, 4, 8, 6}
//	testCipherVect2 := *libunlynx.EncryptIntVector(keys.Public, tab2)
//
//	responses := make([]libunlynx.CipherVector, 3)
//	responses[0] = append(testCipherVect2, testCipherVect2...)
//	responses[1] = append(testCipherVect1, testCipherVect1...)
//	responses[2] = append(testCipherVect2, testCipherVect1...)
//
//	responsesShuffled, pi, beta := libunlynxshuffle.ShuffleSequence(responses, libunlynx.SuiTe.Point().Base(), keys.Public, nil)
//	PublishedShufflingProof := libunlynxshuffle.ShuffleProofCreation(responses, responsesShuffled, libunlynx.SuiTe.Point().Base(), keys.Public, beta, pi)
//	assert.True(t, libunlynxshuffle.ShuffleProofVerification(PublishedShufflingProof, keys.Public))
//
//	PublishedShufflingProof = libunlynxshuffle.ShuffleProofCreation(responses, responses, libunlynx.SuiTe.Point().Base(), keys.Public, beta, pi)
//	assert.False(t, libunlynxshuffle.ShuffleProofVerification(PublishedShufflingProof, keys.Public))
//}
