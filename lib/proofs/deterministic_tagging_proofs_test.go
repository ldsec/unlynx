package proofs_test

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
    cp1 := proofs.DeterministicTagProofCreation(cipherOne, *cipherOneDetTagged, secKey, secKeyNew)
    assert.True(t, proofs.DeterministicTagCheckProof(cp1, pubKey, cipherOne, *cipherOneDetTagged))

    aux := libunlynx.NewCipherText()
    aux.Add(cipherOne, cipherOne)
    assert.False(t, proofs.DeterministicTagCheckProof(cp1, pubKey, *aux, *cipherOneDetTagged))

    aux = libunlynx.NewCipherText()
    aux.Add(cipherOne, cipherOne)
    assert.False(t, proofs.DeterministicTagCheckProof(cp1, pubKey, cipherOne, *aux))
    assert.False(t, proofs.DeterministicTagCheckProof(cp1, pubKeyNew, cipherOne, *cipherOneDetTagged))

    cp1 = proofs.DeterministicTagProofCreation(cipherOne, *cipherOneDetTagged, secKeyNew, secKeyNew)
    assert.False(t, proofs.DeterministicTagCheckProof(cp1, pubKey, cipherOne, *cipherOneDetTagged))

    cp1 = proofs.DeterministicTagProofCreation(cipherOne, *cipherOneDetTagged, secKey, secKey)
    assert.False(t, proofs.DeterministicTagCheckProof(cp1, pubKey, cipherOne, *cipherOneDetTagged))

    // test tag switching at cipherVector level
    TagSwitchedVect := libunlynx.NewCipherVector(2)
    TagSwitchedVect.DeterministicTagging(&cipherVect, secKey, secKeyNew)

    cps1 := proofs.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKey)
    result, _ := proofs.PublishedDeterministicTaggingCheckProof(proofs.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: nil})
    assert.True(t, result)

    cps1 = proofs.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKey)
    result, _ = proofs.PublishedDeterministicTaggingCheckProof(proofs.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: libunlynx.SuiTe.Point().Mul(secKeyNew, libunlynx.SuiTe.Point().Base())})
    assert.True(t, result)

    cps1 = proofs.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKey, secKey)
    result, _ = proofs.PublishedDeterministicTaggingCheckProof(proofs.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: libunlynx.SuiTe.Point().Mul(secKeyNew, libunlynx.SuiTe.Point().Base())})
    assert.False(t, result)

    cps1 = proofs.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKeyNew)
    result, _ = proofs.PublishedDeterministicTaggingCheckProof(proofs.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: libunlynx.SuiTe.Point().Mul(secKeyNew, libunlynx.SuiTe.Point().Base())})
    assert.False(t, result)

    cps1 = proofs.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKey)
    result, _ = proofs.PublishedDeterministicTaggingCheckProof(proofs.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKeyNew, SB: libunlynx.SuiTe.Point().Mul(secKeyNew, libunlynx.SuiTe.Point().Base())})
    assert.False(t, result)

    cps1 = proofs.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKey)
    result, _ = proofs.PublishedDeterministicTaggingCheckProof(proofs.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: libunlynx.SuiTe.Point().Mul(secKey, libunlynx.SuiTe.Point().Base())})
    assert.False(t, result)
}

func TestDeterministicTaggingAdditionProof(t *testing.T) {
    cipherOne = *libunlynx.EncryptInt(pubKey, 10)
    toAdd := libunlynx.SuiTe.Point().Mul(secKey, libunlynx.SuiTe.Point().Base())
    tmp := libunlynx.SuiTe.Point().Add(cipherOne.C, toAdd)

    prf := proofs.DetTagAdditionProofCreation(cipherOne.C, secKey, toAdd, tmp)
    assert.True(t, proofs.DetTagAdditionProofVerification(prf))

    prf = proofs.DetTagAdditionProofCreation(toAdd, secKey, toAdd, tmp)
    assert.False(t, proofs.DetTagAdditionProofVerification(prf))

    prf = proofs.DetTagAdditionProofCreation(cipherOne.C, secKeyNew, toAdd, tmp)
    assert.False(t, proofs.DetTagAdditionProofVerification(prf))

    prf = proofs.DetTagAdditionProofCreation(cipherOne.C, secKey, cipherOne.C, tmp)
    assert.False(t, proofs.DetTagAdditionProofVerification(prf))

    prf = proofs.DetTagAdditionProofCreation(cipherOne.C, secKey, toAdd, toAdd)
    assert.False(t, proofs.DetTagAdditionProofVerification(prf))
}

