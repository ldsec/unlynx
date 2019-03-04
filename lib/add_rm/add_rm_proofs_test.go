package libunlynxaddrm_test

import (
	"testing"

	"github.com/dedis/kyber/util/random"
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
)

//create variables
var secKey = libunlynx.SuiTe.Scalar().Pick(random.New())
var pubKey = libunlynx.SuiTe.Point().Mul(secKey, libunlynx.SuiTe.Point().Base())

var secKeyNew = libunlynx.SuiTe.Scalar().Pick(random.New())
var pubKeyNew = libunlynx.SuiTe.Point().Mul(secKeyNew, libunlynx.SuiTe.Point().Base())

var cipherOne = *libunlynx.EncryptInt(pubKey, 10)

var cipherVect = libunlynx.CipherVector{cipherOne, cipherOne}

func TestAddRmProof(t *testing.T) {
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
	prf := libunlynxproofs.AddRmProofCreation(cipherOne, result, secKeyNew, true)
	assert.True(t, libunlynxproofs.AddRmCheckProof(prf, pubKeyNew, cipherOne, result, true))
	assert.False(t, libunlynxproofs.AddRmCheckProof(prf, pubKey, cipherOne, result, true))
	assert.False(t, libunlynxproofs.AddRmCheckProof(prf, pubKeyNew, result, result, true))
	assert.False(t, libunlynxproofs.AddRmCheckProof(prf, pubKeyNew, cipherOne, cipherOne, true))
	assert.False(t, libunlynxproofs.AddRmCheckProof(prf, pubKeyNew, cipherOne, result, false))

	//subtraction
	result = *libunlynx.NewCipherText()
	cipherOne = *libunlynx.EncryptInt(pubKey, 10)
	tmp = libunlynx.SuiTe.Point().Mul(secKeyNew, cipherOne.K)
	result.K = cipherOne.K
	result.C = libunlynx.SuiTe.Point().Sub(cipherOne.C, tmp)
	prf = libunlynxproofs.AddRmProofCreation(cipherOne, result, secKeyNew, false)
	assert.True(t, libunlynxproofs.AddRmCheckProof(prf, pubKeyNew, cipherOne, result, false))
	assert.False(t, libunlynxproofs.AddRmCheckProof(prf, pubKey, cipherOne, result, false))
	assert.False(t, libunlynxproofs.AddRmCheckProof(prf, pubKeyNew, result, result, false))
	assert.False(t, libunlynxproofs.AddRmCheckProof(prf, pubKeyNew, cipherOne, cipherOne, false))
	assert.False(t, libunlynxproofs.AddRmCheckProof(prf, pubKeyNew, cipherOne, result, true))

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
	prfVectAdd := libunlynxproofs.VectorAddRmProofCreation(cipherArray, resultAdd, secKeyNew, true)
	prfVectAddPub := libunlynxproofs.PublishedAddRmProof{Arp: prfVectAdd, VectBefore: cipherArray, VectAfter: resultAdd, Krm: pubKeyNew, ToAdd: true}
	prfVectSub := libunlynxproofs.VectorAddRmProofCreation(cipherArray, resultSub, secKeyNew, false)
	prfVectSubPub := libunlynxproofs.PublishedAddRmProof{Arp: prfVectSub, VectBefore: cipherArray, VectAfter: resultSub, Krm: pubKeyNew, ToAdd: false}
	assert.True(t, libunlynxproofs.PublishedAddRmCheckProof(prfVectAddPub))
	assert.True(t, libunlynxproofs.PublishedAddRmCheckProof(prfVectSubPub))

	prfVectAddPub = libunlynxproofs.PublishedAddRmProof{Arp: prfVectAdd, VectBefore: resultAdd, VectAfter: resultAdd, Krm: pubKeyNew, ToAdd: true}
	prfVectSubPub = libunlynxproofs.PublishedAddRmProof{Arp: prfVectSub, VectBefore: resultAdd, VectAfter: resultSub, Krm: pubKeyNew, ToAdd: false}
	assert.False(t, libunlynxproofs.PublishedAddRmCheckProof(prfVectAddPub))
	assert.False(t, libunlynxproofs.PublishedAddRmCheckProof(prfVectSubPub))

	prfVectAddPub = libunlynxproofs.PublishedAddRmProof{Arp: prfVectAdd, VectBefore: cipherArray, VectAfter: resultSub, Krm: pubKeyNew, ToAdd: true}
	prfVectSubPub = libunlynxproofs.PublishedAddRmProof{Arp: prfVectSub, VectBefore: cipherArray, VectAfter: resultAdd, Krm: pubKeyNew, ToAdd: false}
	assert.False(t, libunlynxproofs.PublishedAddRmCheckProof(prfVectAddPub))
	assert.False(t, libunlynxproofs.PublishedAddRmCheckProof(prfVectSubPub))

	prfVectAddPub = libunlynxproofs.PublishedAddRmProof{Arp: prfVectAdd, VectBefore: cipherArray, VectAfter: resultAdd, Krm: pubKey, ToAdd: true}
	prfVectSubPub = libunlynxproofs.PublishedAddRmProof{Arp: prfVectSub, VectBefore: cipherArray, VectAfter: resultSub, Krm: pubKey, ToAdd: false}
	assert.False(t, libunlynxproofs.PublishedAddRmCheckProof(prfVectAddPub))
	assert.False(t, libunlynxproofs.PublishedAddRmCheckProof(prfVectSubPub))

	prfVectAddPub = libunlynxproofs.PublishedAddRmProof{Arp: prfVectAdd, VectBefore: cipherArray, VectAfter: resultAdd, Krm: pubKeyNew, ToAdd: false}
	prfVectSubPub = libunlynxproofs.PublishedAddRmProof{Arp: prfVectSub, VectBefore: cipherArray, VectAfter: resultSub, Krm: pubKeyNew, ToAdd: true}
	assert.False(t, libunlynxproofs.PublishedAddRmCheckProof(prfVectAddPub))
	assert.False(t, libunlynxproofs.PublishedAddRmCheckProof(prfVectSubPub))

}
