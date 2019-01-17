package libunlynxdetertag_test

import (
	"testing"

	"github.com/dedis/kyber/util/key"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/deterministic_tag"
	"github.com/stretchr/testify/assert"
)

func TestDeterministicTaggingProof(t *testing.T) {
	keys := key.NewKeyPair(libunlynx.SuiTe)
	pubKey, secKey := keys.Public, keys.Private

	secretContrib := key.NewKeyPair(libunlynx.SuiTe).Private
	pubKeyNew := key.NewKeyPair(libunlynx.SuiTe).Public

	cipherOne := *libunlynx.EncryptInt(pubKey, 10)

	// test tagging at ciphertext level
	cipherOneDetTagged := libunlynxdetertag.DeterministicTagElement(cipherOne, secKey, secretContrib)
	dtp := libunlynxdetertag.DeterministicTagProofCreation(cipherOne, *cipherOneDetTagged, secKey, secretContrib)
	assert.True(t, libunlynxdetertag.DeterministicTagCheckProof(dtp, pubKey, cipherOne, *cipherOneDetTagged))

	aux := libunlynx.NewCipherText()
	aux.Add(cipherOne, cipherOne)
	assert.False(t, libunlynxdetertag.DeterministicTagCheckProof(dtp, pubKey, *aux, *cipherOneDetTagged))

	aux = libunlynx.NewCipherText()
	aux.Add(cipherOne, cipherOne)
	assert.False(t, libunlynxdetertag.DeterministicTagCheckProof(dtp, pubKey, cipherOne, *aux))
	assert.False(t, libunlynxdetertag.DeterministicTagCheckProof(dtp, pubKeyNew, cipherOne, *cipherOneDetTagged))

	dtp = libunlynxdetertag.DeterministicTagProofCreation(cipherOne, *cipherOneDetTagged, secretContrib, secretContrib)
	assert.False(t, libunlynxdetertag.DeterministicTagCheckProof(dtp, pubKey, cipherOne, *cipherOneDetTagged))

	dtp = libunlynxdetertag.DeterministicTagProofCreation(cipherOne, *cipherOneDetTagged, secKey, secKey)
	assert.False(t, libunlynxdetertag.DeterministicTagCheckProof(dtp, pubKey, cipherOne, *cipherOneDetTagged))

	// test tag at ciphervector level
	cv := libunlynx.NewCipherVector(2)
	cvDetTagged := libunlynxdetertag.DeterministicTagSequence(*cv, secKey, secretContrib)

	dtpList := libunlynxdetertag.VectorDeterministicTagProofCreation(*cv, *cvDetTagged, secretContrib, secKey)
	result, _ := libunlynxdetertag.PublishedDeterministicTaggingCheckProof(libunlynxdetertag.PublishedDeterministicTaggingProof{Dhp: dtpList, VectBefore: *cv, VectAfter: *cvDetTagged, K: pubKey, SB: nil})
	assert.True(t, result)

	dtpList = libunlynxdetertag.VectorDeterministicTagProofCreation(*cv, *cvDetTagged, secretContrib, secKey)
	result, _ = libunlynxdetertag.PublishedDeterministicTaggingCheckProof(libunlynxdetertag.PublishedDeterministicTaggingProof{Dhp: dtpList, VectBefore: *cv, VectAfter: *cvDetTagged, K: pubKey, SB: libunlynx.SuiTe.Point().Mul(secretContrib, libunlynx.SuiTe.Point().Base())})
	assert.True(t, result)

	dtpList = libunlynxdetertag.VectorDeterministicTagProofCreation(*cv, *cvDetTagged, secKey, secKey)
	result, _ = libunlynxdetertag.PublishedDeterministicTaggingCheckProof(libunlynxdetertag.PublishedDeterministicTaggingProof{Dhp: dtpList, VectBefore: *cv, VectAfter: *cvDetTagged, K: pubKey, SB: libunlynx.SuiTe.Point().Mul(secretContrib, libunlynx.SuiTe.Point().Base())})
	assert.False(t, result)

	dtpList = libunlynxdetertag.VectorDeterministicTagProofCreation(*cv, *cvDetTagged, secretContrib, secretContrib)
	result, _ = libunlynxdetertag.PublishedDeterministicTaggingCheckProof(libunlynxdetertag.PublishedDeterministicTaggingProof{Dhp: dtpList, VectBefore: *cv, VectAfter: *cvDetTagged, K: pubKey, SB: libunlynx.SuiTe.Point().Mul(secretContrib, libunlynx.SuiTe.Point().Base())})
	assert.False(t, result)

	dtpList = libunlynxdetertag.VectorDeterministicTagProofCreation(*cv, *cvDetTagged, secretContrib, secKey)
	result, _ = libunlynxdetertag.PublishedDeterministicTaggingCheckProof(libunlynxdetertag.PublishedDeterministicTaggingProof{Dhp: dtpList, VectBefore: *cv, VectAfter: *cvDetTagged, K: pubKeyNew, SB: libunlynx.SuiTe.Point().Mul(secretContrib, libunlynx.SuiTe.Point().Base())})
	assert.False(t, result)

	dtpList = libunlynxdetertag.VectorDeterministicTagProofCreation(*cv, *cvDetTagged, secretContrib, secKey)
	result, _ = libunlynxdetertag.PublishedDeterministicTaggingCheckProof(libunlynxdetertag.PublishedDeterministicTaggingProof{Dhp: dtpList, VectBefore: *cv, VectAfter: *cvDetTagged, K: pubKey, SB: libunlynx.SuiTe.Point().Mul(secKey, libunlynx.SuiTe.Point().Base())})
	assert.False(t, result)
}

func TestDeterministicTaggingAdditionProof(t *testing.T) {
	keys := key.NewKeyPair(libunlynx.SuiTe)
	pubKey, secKey := keys.Public, keys.Private

	secretContrib := key.NewKeyPair(libunlynx.SuiTe).Private

	cipherOne := *libunlynx.EncryptInt(pubKey, 10)
	toAdd := libunlynx.SuiTe.Point().Mul(secKey, libunlynx.SuiTe.Point().Base())
	tmp := libunlynx.SuiTe.Point().Add(cipherOne.C, toAdd)

	prf := libunlynxdetertag.DetTagAdditionProofCreation(cipherOne.C, secKey, toAdd, tmp)
	assert.True(t, libunlynxdetertag.DetTagAdditionProofVerification(prf))

	prf = libunlynxdetertag.DetTagAdditionProofCreation(toAdd, secKey, toAdd, tmp)
	assert.False(t, libunlynxdetertag.DetTagAdditionProofVerification(prf))

	prf = libunlynxdetertag.DetTagAdditionProofCreation(cipherOne.C, secretContrib, toAdd, tmp)
	assert.False(t, libunlynxdetertag.DetTagAdditionProofVerification(prf))

	prf = libunlynxdetertag.DetTagAdditionProofCreation(cipherOne.C, secKey, cipherOne.C, tmp)
	assert.False(t, libunlynxdetertag.DetTagAdditionProofVerification(prf))

	prf = libunlynxdetertag.DetTagAdditionProofCreation(cipherOne.C, secKey, toAdd, toAdd)
	assert.False(t, libunlynxdetertag.DetTagAdditionProofVerification(prf))
}
