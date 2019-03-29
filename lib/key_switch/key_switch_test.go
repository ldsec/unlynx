package libunlynxkeyswitch_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3"

	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/key_switch"
	"go.dedis.ch/kyber/v3/util/key"
)

// TesKeySwitchingProof test key switching of a sequence of ciphertexts
func TestKeySwitchSequence(t *testing.T) {
	keysTarget := key.NewKeyPair(libunlynx.SuiTe)

	keys := key.NewKeyPair(libunlynx.SuiTe)
	ct1 := libunlynx.EncryptInt(keys.Public, int64(1))
	ct2 := libunlynx.EncryptInt(keys.Public, int64(2))

	rBs := []kyber.Point{ct1.K, ct2.K}

	cv, _, _, _ := libunlynxkeyswitch.KeySwitchSequence(keysTarget.Public, rBs, keys.Private)
	cv[0].C.Add(cv[0].C, ct1.C)
	cv[1].C.Add(cv[1].C, ct2.C)
	result := libunlynx.DecryptIntVector(keysTarget.Private, &cv)

	assert.Equal(t, int64(1), result[0])
	assert.Equal(t, int64(2), result[1])
}
