package libunlynxdetertag_test

import (
	"testing"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/key"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/deterministic_tag"
	"github.com/stretchr/testify/assert"
)

func TestDeterministicTagProofCreation(t *testing.T) {
	keys := key.NewKeyPair(libunlynx.SuiTe)
	pubKey, secKey := keys.Public, keys.Private
	pubKeyNew := key.NewKeyPair(libunlynx.SuiTe).Public

	secretContrib := key.NewKeyPair(libunlynx.SuiTe).Private

	cipherOne := *libunlynx.EncryptInt(pubKey, 10)

	// test tagging at ciphertext level
	cipherOneDetTagged := libunlynxdetertag.DeterministicTag(cipherOne, secKey, secretContrib)
	dtp := libunlynxdetertag.DeterministicTagCrProofCreation(cipherOne, cipherOneDetTagged, pubKey, secKey, secretContrib)
	sb := libunlynx.SuiTe.Point().Mul(secretContrib, libunlynx.SuiTe.Point().Base())
	assert.True(t, libunlynxdetertag.DeterministicTagCrProofVerification(dtp, pubKey, sb))

	assert.False(t, libunlynxdetertag.DeterministicTagCrProofVerification(dtp, pubKey, pubKey))
	assert.False(t, libunlynxdetertag.DeterministicTagCrProofVerification(dtp, pubKeyNew, sb))

	auxC := dtp.Ciminus11Si
	dtp.Ciminus11Si = pubKey
	assert.False(t, libunlynxdetertag.DeterministicTagCrProofVerification(dtp, pubKey, sb))
	dtp.Ciminus11Si = auxC

	auxAft := dtp.CTaft
	dtp.CTaft = dtp.CTbef
	assert.False(t, libunlynxdetertag.DeterministicTagCrProofVerification(dtp, pubKeyNew, sb))
	dtp.CTaft = auxAft

	auxBef := dtp.CTbef
	dtp.CTbef = dtp.CTaft
	assert.False(t, libunlynxdetertag.DeterministicTagCrProofVerification(dtp, pubKeyNew, sb))
	dtp.CTbef = auxBef

	assert.True(t, libunlynxdetertag.DeterministicTagCrProofVerification(dtp, pubKey, sb))

	// test tag at ciphervector level
	cv := libunlynx.NewCipherVector(2)
	cvDetTagged := libunlynxdetertag.DeterministicTagSequence(*cv, secKey, secretContrib)

	dtpList := libunlynxdetertag.DeterministicTagCrListProofCreation(*cv, cvDetTagged, pubKey, secKey, secretContrib)
	assert.True(t, libunlynxdetertag.DeterministicTagCrListProofVerification(dtpList, 1.0))

	dtpList.K = pubKeyNew
	assert.False(t, libunlynxdetertag.DeterministicTagCrListProofVerification(dtpList, 1.0))
	dtpList.K = pubKey

	auxSB := dtpList.SB
	dtpList.SB = pubKeyNew
	assert.False(t, libunlynxdetertag.DeterministicTagCrListProofVerification(dtpList, 1.0))
	dtpList.SB = auxSB

	auxEl := dtpList.List[0]
	dtpList.List[0].CTbef = cipherOne
	assert.False(t, libunlynxdetertag.DeterministicTagCrListProofVerification(dtpList, 1.0))
	dtpList.List[0] = auxEl

	assert.True(t, libunlynxdetertag.DeterministicTagCrListProofVerification(dtpList, 1.0))
}

func TestDeterministicTaggingAdditionProof(t *testing.T) {
	keys := key.NewKeyPair(libunlynx.SuiTe)
	pubKey, secKey := keys.Public, keys.Private

	secretContrib := key.NewKeyPair(libunlynx.SuiTe).Private

	cipherOne := *libunlynx.EncryptInt(pubKey, 10)
	toAdd := libunlynx.SuiTe.Point().Mul(secKey, libunlynx.SuiTe.Point().Base())
	tmp := libunlynx.SuiTe.Point().Add(cipherOne.C, toAdd)

	prf := libunlynxdetertag.DeterministicTagAdditionProofCreation(cipherOne.C, secKey, toAdd, tmp)
	assert.True(t, libunlynxdetertag.DeterministicTagAdditionProofVerification(prf))

	prf = libunlynxdetertag.DeterministicTagAdditionProofCreation(toAdd, secKey, toAdd, tmp)
	assert.False(t, libunlynxdetertag.DeterministicTagAdditionProofVerification(prf))

	prf = libunlynxdetertag.DeterministicTagAdditionProofCreation(cipherOne.C, secretContrib, toAdd, tmp)
	assert.False(t, libunlynxdetertag.DeterministicTagAdditionProofVerification(prf))

	prf = libunlynxdetertag.DeterministicTagAdditionProofCreation(cipherOne.C, secKey, cipherOne.C, tmp)
	assert.False(t, libunlynxdetertag.DeterministicTagAdditionProofVerification(prf))

	prf = libunlynxdetertag.DeterministicTagAdditionProofCreation(cipherOne.C, secKey, toAdd, toAdd)
	assert.False(t, libunlynxdetertag.DeterministicTagAdditionProofVerification(prf))

	prfList := libunlynxdetertag.DeterministicTagAdditionListProofCreation([]kyber.Point{cipherOne.C, cipherOne.C}, []kyber.Scalar{secKey, secKey}, []kyber.Point{toAdd, toAdd}, []kyber.Point{tmp, tmp})
	assert.True(t, libunlynxdetertag.DeterministicTagAdditionListProofVerification(prfList, 1.0))
}
