package libunlynxdetertag

import (
	"testing"

	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
)

// TestDeterministicTag tests the deterministic tagging of a vector (and consequently of a ciphertext)
func TestDeterministicTagSequence(t *testing.T) {
	const N = 5

	groupKey, private, _ := libunlynx.GenKeys(N)
	_, secretPrivate, _ := libunlynx.GenKeys(N)

	target := []int64{-8358645081376817152, -8358645081376817152, 2, 3, 2, 5}
	cv := *libunlynx.EncryptIntVector(groupKey, target)
	for n := 0; n < N; n++ {
		tmp := DeterministicTagSequence(cv, private[n], secretPrivate[n])
		cv = tmp
	}

	assert.True(t, cv[0].C.Equal(cv[1].C))
	assert.True(t, cv[2].C.Equal(cv[4].C))
	assert.False(t, cv[0].C.Equal(cv[3].C))
}
