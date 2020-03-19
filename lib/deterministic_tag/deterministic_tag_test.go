package libunlynxdetertag_test

import (
	"testing"

	"github.com/ldsec/unlynx/lib/deterministic_tag"

	"github.com/ldsec/unlynx/lib"
	"github.com/stretchr/testify/assert"
)

// TestDeterministicTag tests the deterministic tagging of a vector (and consequently of a ciphertext)
func TestDeterministicTagSequence(t *testing.T) {
	const N = 5

	K, private, _ := libunlynx.GenKeys(N)
	_, secretPrivate, _ := libunlynx.GenKeys(N)

	target := []int64{-8358645081376817152, -8358645081376817152, 2, 3, 2, 5}
	cv := *libunlynx.EncryptIntVector(K, target)
	for n := 0; n < N; n++ {
		cv = libunlynxdetertag.DeterministicTagSequence(cv, private[n], secretPrivate[n])
	}

	assert.True(t, cv[0].C.Equal(cv[1].C))
	assert.True(t, cv[2].C.Equal(cv[4].C))
	assert.False(t, cv[0].C.Equal(cv[3].C))
}

func TestCipherVectorToDeterministicTag(t *testing.T) {
	K, private, _ := libunlynx.GenKeys(1)
	_, secretPrivate, _ := libunlynx.GenKeys(1)

	target := []int64{-8358645081376817152, -8358645081376817152, 2, 3, 2, 5}
	cv1 := *libunlynx.EncryptIntVector(K, target)
	cv2 := *libunlynx.EncryptIntVector(K, target)

	gk1, _, err := libunlynxdetertag.CipherVectorToDeterministicTag(cv1, private[0], secretPrivate[0], K, false)
	assert.NoError(t, err)
	gk2, _, err := libunlynxdetertag.CipherVectorToDeterministicTag(cv2, private[0], secretPrivate[0], K, false)
	assert.NoError(t, err)

	assert.Equal(t, gk1, gk2)
}
