package libunlynxkeyswitch_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dedis/kyber/util/key"
	"github.com/lca1/unlynx/lib/key_switch"

	"github.com/dedis/kyber"
	"github.com/lca1/unlynx/lib"
)

// TesKeySwitchingProof test the creation and verification of key switching proofs
func TestKeySwitchingProof(t *testing.T) {
	keysTarget := key.NewKeyPair(libunlynx.SuiTe)

	keys := key.NewKeyPair(libunlynx.SuiTe)

	ct1 := libunlynx.EncryptInt(keys.Public, int64(1))
	ct2 := libunlynx.EncryptInt(keys.Public, int64(2))
	rBs := []kyber.Point{ct1.K, ct2.K}

	_, ks2s, rBNegs, vis := libunlynxkeyswitch.KeySwitchSequence(keysTarget.Public, rBs, keys.Private)

	// verify a 'correct' list proof
	pkslp := libunlynxkeyswitch.KeySwitchListProofCreation(keys.Public, keysTarget.Public, keys.Private, ks2s, rBNegs, vis)

	verif := libunlynxkeyswitch.KeySwitchListProofVerification(pkslp, 1.0)

	assert.True(t, verif)

	// verifiy an 'incorrect' list proof
	ct3 := libunlynx.EncryptInt(keys.Public, int64(3))
	pkslp.Prs[0].K = ct3.K
	verif = libunlynxkeyswitch.KeySwitchListProofVerification(pkslp, 1.0)
	assert.False(t, verif)

	pkslp.Prs[0].K = keysTarget.Public
	verif = libunlynxkeyswitch.KeySwitchListProofVerification(pkslp, 1.0)
	assert.False(t, verif)

	pkslp.Prs[0].Ks2 = keysTarget.Public
	verif = libunlynxkeyswitch.KeySwitchListProofVerification(pkslp, 1.0)
	assert.False(t, verif)

	pkslp.Prs[0].ViB = keysTarget.Public
	verif = libunlynxkeyswitch.KeySwitchListProofVerification(pkslp, 1.0)
	assert.False(t, verif)

	pkslp.Prs[0].Proof = []byte{2}
	verif = libunlynxkeyswitch.KeySwitchListProofVerification(pkslp, 1.0)
	assert.False(t, verif)
}