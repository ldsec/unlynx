package libunlynxaddrm_test

import (
	"testing"

	"github.com/lca1/unlynx/lib/add_rm"

	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3/util/random"
)

func TestAddRmProof(t *testing.T) {
	var secKey = libunlynx.SuiTe.Scalar().Pick(random.New())
	var pubKey = libunlynx.SuiTe.Point().Mul(secKey, libunlynx.SuiTe.Point().Base())

	var secKeyNew = libunlynx.SuiTe.Scalar().Pick(random.New())
	var pubKeyNew = libunlynx.SuiTe.Point().Mul(secKeyNew, libunlynx.SuiTe.Point().Base())

	var cipherOne = *libunlynx.EncryptInt(pubKey, 10)

	//test  at ciphertext level
	result := *libunlynx.NewCipherText()
	cipherOne = *libunlynx.EncryptInt(pubKey, 10)
	cipherArray := make([]libunlynx.CipherText, 2)
	cipherArray[0] = cipherOne
	cipherArray[1] = cipherOne

	tmp := libunlynx.SuiTe.Point().Mul(secKeyNew, cipherOne.K)
	result.K = cipherOne.K

	//addition
	result.C = libunlynx.SuiTe.Point().Add(cipherOne.C, tmp)
	prf := libunlynxaddrm.AddRmProofCreation(cipherOne, result, pubKeyNew, secKeyNew, true)
	assert.True(t, libunlynxaddrm.AddRmProofVerification(prf, pubKeyNew, true))
	assert.False(t, libunlynxaddrm.AddRmProofVerification(prf, pubKey, true))
	assert.False(t, libunlynxaddrm.AddRmProofVerification(prf, pubKeyNew, false))

	//subtraction
	result = *libunlynx.NewCipherText()
	cipherOne = *libunlynx.EncryptInt(pubKey, 10)
	tmp = libunlynx.SuiTe.Point().Mul(secKeyNew, cipherOne.K)
	result.K = cipherOne.K
	result.C = libunlynx.SuiTe.Point().Sub(cipherOne.C, tmp)
	prf = libunlynxaddrm.AddRmProofCreation(cipherOne, result, pubKeyNew, secKeyNew, false)
	assert.True(t, libunlynxaddrm.AddRmProofVerification(prf, pubKeyNew, false))
	assert.False(t, libunlynxaddrm.AddRmProofVerification(prf, pubKey, false))
	assert.False(t, libunlynxaddrm.AddRmProofVerification(prf, pubKeyNew, true))

	resultAdd := make([]libunlynx.CipherText, 2)
	resultSub := make([]libunlynx.CipherText, 2)

	for j := 0; j < len(cipherArray); j++ {
		w := libunlynx.CipherText{K: cipherArray[j].K, C: cipherArray[j].C}

		tmp := libunlynx.SuiTe.Point().Mul(secKeyNew, w.K)

		add := libunlynx.CipherText{K: w.K, C: libunlynx.SuiTe.Point().Add(w.C, tmp)}
		sub := libunlynx.CipherText{K: w.K, C: libunlynx.SuiTe.Point().Sub(w.C, tmp)}

		resultAdd[j] = add
		resultSub[j] = sub
	}

	// Test 1
	prfVectAdd := libunlynxaddrm.AddRmListProofCreation(cipherArray, resultAdd, pubKeyNew, secKeyNew, true)
	prfVectSub := libunlynxaddrm.AddRmListProofCreation(cipherArray, resultSub, pubKeyNew, secKeyNew, false)

	assert.True(t, libunlynxaddrm.AddRmListProofVerification(prfVectAdd, 1.0))
	assert.True(t, libunlynxaddrm.AddRmListProofVerification(prfVectSub, 1.0))

	// Test 2
	prfVectAdd.List[0].CtBef = resultAdd[0]
	prfVectAdd.List[0].CtAft = resultAdd[0]

	prfVectSub.List[0].CtBef = resultAdd[0]
	prfVectSub.List[0].CtAft = resultSub[0]

	assert.False(t, libunlynxaddrm.AddRmListProofVerification(prfVectAdd, 1.0))
	assert.False(t, libunlynxaddrm.AddRmListProofVerification(prfVectSub, 1.0))

	// Test 3
	prfVectAdd.List[0].CtBef = cipherArray[0]
	prfVectAdd.List[0].CtAft = resultSub[0]

	prfVectSub.List[0].CtBef = cipherArray[0]
	prfVectSub.List[0].CtAft = resultAdd[0]

	assert.False(t, libunlynxaddrm.AddRmListProofVerification(prfVectAdd, 1.0))
	assert.False(t, libunlynxaddrm.AddRmListProofVerification(prfVectSub, 1.0))

	// Test 4
	prfVectAdd.List[0].CtAft = resultAdd[0]
	prfVectAdd.Krm = pubKey

	prfVectSub.List[0].CtAft = resultSub[0]
	prfVectSub.Krm = pubKey

	assert.False(t, libunlynxaddrm.AddRmListProofVerification(prfVectAdd, 1.0))
	assert.False(t, libunlynxaddrm.AddRmListProofVerification(prfVectSub, 1.0))

	// Test 5
	prfVectAdd.Krm = pubKeyNew
	prfVectAdd.ToAdd = false

	prfVectSub.Krm = pubKeyNew
	prfVectSub.ToAdd = true

	assert.False(t, libunlynxaddrm.AddRmListProofVerification(prfVectAdd, 1.0))
	assert.False(t, libunlynxaddrm.AddRmListProofVerification(prfVectSub, 1.0))
}
