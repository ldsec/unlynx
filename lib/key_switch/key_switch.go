package libunlynxkeyswitch

import (
	"github.com/lca1/unlynx/lib"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/random"
)

// KeySwitchSequence implements the key switching operation on a ciphertext.
func KeySwitchSequence(targetPubKey kyber.Point, rBs []kyber.Point, secretKey kyber.Scalar) (libunlynx.CipherVector, []kyber.Point, []kyber.Point, []kyber.Scalar) {
	// rBs is the left part of the CipherTexts to be keyswitched
	length := len(rBs)

	ks2s := make([]kyber.Point, length)
	rBNegs := make([]kyber.Point, length)
	vis := make([]kyber.Scalar, length)

	wg := libunlynx.StartParallelize(length)
	cv := libunlynx.NewCipherVector(len(rBs))
	for i, v := range rBs {
		go func(i int, v kyber.Point) {
			defer wg.Done()

			vi := libunlynx.SuiTe.Scalar().Pick(random.New())
			(*cv)[i].K = libunlynx.SuiTe.Point().Mul(vi, libunlynx.SuiTe.Point().Base())
			rbNeg := libunlynx.SuiTe.Point().Neg(rBs[i])
			rbkNeg := libunlynx.SuiTe.Point().Mul(secretKey, rbNeg)
			viNewK := libunlynx.SuiTe.Point().Mul(vi, targetPubKey)
			(*cv)[i].C = libunlynx.SuiTe.Point().Add(rbkNeg, viNewK)

			//for the proof
			ks2s[i] = (*cv)[i].C
			rBNegs[i] = rbNeg
			vis[i] = vi
		}(i, v)
	}
	libunlynx.EndParallelize(wg)

	return *cv, ks2s, rBNegs, vis
}
