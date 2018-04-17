package libunlynxproofs_test

import (
    "github.com/lca1/unlynx/lib"
    "github.com/lca1/unlynx/lib/proofs"
    "github.com/stretchr/testify/assert"
    "testing"
)

func TestDeterministicTaggingProof(t *testing.T) {
    // test tagging switching at ciphertext level
    cipherOneDetTagged := libunlynx.NewCipherText()
    cipherOneDetTagged.DeterministicTagging(&cipherOne, secKey, secKeyNew)
    cp1 := libunlynxproofs.DeterministicTagProofCreation(cipherOne, *cipherOneDetTagged, secKey, secKeyNew)
    assert.True(t, libunlynxproofs.DeterministicTagCheckProof(cp1, pubKey, cipherOne, *cipherOneDetTagged))

    aux := libunlynx.NewCipherText()
    aux.Add(cipherOne, cipherOne)
    assert.False(t, libunlynxproofs.DeterministicTagCheckProof(cp1, pubKey, *aux, *cipherOneDetTagged))

    aux = libunlynx.NewCipherText()
    aux.Add(cipherOne, cipherOne)
    assert.False(t, libunlynxproofs.DeterministicTagCheckProof(cp1, pubKey, cipherOne, *aux))
    assert.False(t, libunlynxproofs.DeterministicTagCheckProof(cp1, pubKeyNew, cipherOne, *cipherOneDetTagged))

    cp1 = libunlynxproofs.DeterministicTagProofCreation(cipherOne, *cipherOneDetTagged, secKeyNew, secKeyNew)
    assert.False(t, libunlynxproofs.DeterministicTagCheckProof(cp1, pubKey, cipherOne, *cipherOneDetTagged))

    cp1 = libunlynxproofs.DeterministicTagProofCreation(cipherOne, *cipherOneDetTagged, secKey, secKey)
    assert.False(t, libunlynxproofs.DeterministicTagCheckProof(cp1, pubKey, cipherOne, *cipherOneDetTagged))

    // test tag switching at cipherVector level
    TagSwitchedVect := libunlynx.NewCipherVector(2)
    TagSwitchedVect.DeterministicTagging(&cipherVect, secKey, secKeyNew)

    cps1 := libunlynxproofs.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKey)
    result, _ := libunlynxproofs.PublishedDeterministicTaggingCheckProof(libunlynxproofs.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: nil})
    assert.True(t, result)

    cps1 = libunlynxproofs.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKey)
    result, _ = libunlynxproofs.PublishedDeterministicTaggingCheckProof(libunlynxproofs.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: libunlynx.SuiTe.Point().Mul(secKeyNew, libunlynx.SuiTe.Point().Base())})
    assert.True(t, result)

    cps1 = libunlynxproofs.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKey, secKey)
    result, _ = libunlynxproofs.PublishedDeterministicTaggingCheckProof(libunlynxproofs.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: libunlynx.SuiTe.Point().Mul(secKeyNew, libunlynx.SuiTe.Point().Base())})
    assert.False(t, result)

    cps1 = libunlynxproofs.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKeyNew)
    result, _ = libunlynxproofs.PublishedDeterministicTaggingCheckProof(libunlynxproofs.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: libunlynx.SuiTe.Point().Mul(secKeyNew, libunlynx.SuiTe.Point().Base())})
    assert.False(t, result)

    cps1 = libunlynxproofs.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKey)
    result, _ = libunlynxproofs.PublishedDeterministicTaggingCheckProof(libunlynxproofs.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKeyNew, SB: libunlynx.SuiTe.Point().Mul(secKeyNew, libunlynx.SuiTe.Point().Base())})
    assert.False(t, result)

    cps1 = libunlynxproofs.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKey)
    result, _ = libunlynxproofs.PublishedDeterministicTaggingCheckProof(libunlynxproofs.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: libunlynx.SuiTe.Point().Mul(secKey, libunlynx.SuiTe.Point().Base())})
    assert.False(t, result)
}

func TestDeterministicTaggingAdditionProof(t *testing.T) {
    cipherOne = *libunlynx.EncryptInt(pubKey, 10)
    toAdd := libunlynx.SuiTe.Point().Mul(secKey, libunlynx.SuiTe.Point().Base())
    tmp := libunlynx.SuiTe.Point().Add(cipherOne.C, toAdd)

    prf := libunlynxproofs.DetTagAdditionProofCreation(cipherOne.C, secKey, toAdd, tmp)
    assert.True(t, libunlynxproofs.DetTagAdditionProofVerification(prf))

    prf = libunlynxproofs.DetTagAdditionProofCreation(toAdd, secKey, toAdd, tmp)
    assert.False(t, libunlynxproofs.DetTagAdditionProofVerification(prf))

    prf = libunlynxproofs.DetTagAdditionProofCreation(cipherOne.C, secKeyNew, toAdd, tmp)
    assert.False(t, libunlynxproofs.DetTagAdditionProofVerification(prf))

    prf = libunlynxproofs.DetTagAdditionProofCreation(cipherOne.C, secKey, cipherOne.C, tmp)
    assert.False(t, libunlynxproofs.DetTagAdditionProofVerification(prf))

    prf = libunlynxproofs.DetTagAdditionProofCreation(cipherOne.C, secKey, toAdd, toAdd)
    assert.False(t, libunlynxproofs.DetTagAdditionProofVerification(prf))
}

