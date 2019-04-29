package libunlynxkeyswitch

import (
	"sync"

	"github.com/lca1/unlynx/lib"
	"go.dedis.ch/kyber/v3"

	"go.dedis.ch/kyber/v3/util/random"
)

// KeySwitchSequence implements the key switching operation on a ciphervector.
func KeySwitchSequence(targetPubKey kyber.Point, rBs []kyber.Point, secretKey kyber.Scalar) (libunlynx.CipherVector, []kyber.Point, []kyber.Point, []kyber.Scalar) {
	// rBs is the left part of the CipherTexts to be keyswitched
	length := len(rBs)

	ks2s := make([]kyber.Point, length)
	rBNegs := make([]kyber.Point, length)
	vis := make([]kyber.Scalar, length)
	cv := libunlynx.NewCipherVector(len(rBs))

	var wg sync.WaitGroup

	for i := 0; i < len(rBs); i = i + libunlynx.VPARALLELIZE {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < libunlynx.VPARALLELIZE && (j+i < len(rBs)); j++ {
				var ct libunlynx.CipherText
				ct, rBNegs[i+j], vis[i+j] = KeySwitch(targetPubKey, rBs[i+j], secretKey)
				ks2s[i+j] = ct.C
				(*cv)[i+j] = ct
			}
		}(i)
	}
	wg.Wait()

	return *cv, ks2s, rBNegs, vis
}

// KeySwitch the second step in the distributed deterministic tagging process (the cycle round) on a ciphertext.
func KeySwitch(targetPubKey kyber.Point, rB kyber.Point, secretKey kyber.Scalar) (libunlynx.CipherText, kyber.Point, kyber.Scalar) {
	ct := libunlynx.NewCipherText()

	vi := libunlynx.SuiTe.Scalar().Pick(random.New())
	ct.K = libunlynx.SuiTe.Point().Mul(vi, libunlynx.SuiTe.Point().Base())
	rbNeg := libunlynx.SuiTe.Point().Neg(rB)
	rbkNeg := libunlynx.SuiTe.Point().Mul(secretKey, rbNeg)
	viNewK := libunlynx.SuiTe.Point().Mul(vi, targetPubKey)
	ct.C = libunlynx.SuiTe.Point().Add(rbkNeg, viNewK)

	return *ct, rbNeg, vi
}
