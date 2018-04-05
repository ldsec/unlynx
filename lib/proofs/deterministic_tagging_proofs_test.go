package proofs

import (
    "github.com/lca1/unlynx/lib"
    "github.com/stretchr/testify/assert"
    "testing"
)

func TestDeterministicTaggingProof(t *testing.T) {
    // test tagging switching at ciphertext level
    cipherOneDetTagged := libunlynx.NewCipherText()
    cipherOneDetTagged.DeterministicTagging(&cipherOne, secKey, secKeyNew)
    cp1 := DeterministicTagProofCreation(cipherOne, *cipherOneDetTagged, secKey, secKeyNew)
    assert.True(t, DeterministicTagCheckProof(cp1, pubKey, cipherOne, *cipherOneDetTagged))

    aux := libunlynx.NewCipherText()
    aux.Add(cipherOne, cipherOne)
    assert.False(t, DeterministicTagCheckProof(cp1, pubKey, *aux, *cipherOneDetTagged))

    aux = libunlynx.NewCipherText()
    aux.Add(cipherOne, cipherOne)
    assert.False(t, DeterministicTagCheckProof(cp1, pubKey, cipherOne, *aux))
    assert.False(t, DeterministicTagCheckProof(cp1, pubKeyNew, cipherOne, *cipherOneDetTagged))

    cp1 = DeterministicTagProofCreation(cipherOne, *cipherOneDetTagged, secKeyNew, secKeyNew)
    assert.False(t, DeterministicTagCheckProof(cp1, pubKey, cipherOne, *cipherOneDetTagged))

    cp1 = DeterministicTagProofCreation(cipherOne, *cipherOneDetTagged, secKey, secKey)
    assert.False(t, DeterministicTagCheckProof(cp1, pubKey, cipherOne, *cipherOneDetTagged))

    // test tag switching at cipherVector level
    TagSwitchedVect := libunlynx.NewCipherVector(2)
    TagSwitchedVect.DeterministicTagging(&cipherVect, secKey, secKeyNew)

    cps1 := VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKey)
    result, _ := PublishedDeterministicTaggingCheckProof(PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: nil})
    assert.True(t, result)

    cps1 = VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKey)
    result, _ = PublishedDeterministicTaggingCheckProof(PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: libunlynx.SuiTe.Point().Mul(secKeyNew, libunlynx.SuiTe.Point().Base())})
    assert.True(t, result)

    cps1 = VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKey, secKey)
    result, _ = PublishedDeterministicTaggingCheckProof(PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: libunlynx.SuiTe.Point().Mul(secKeyNew, libunlynx.SuiTe.Point().Base())})
    assert.False(t, result)

    cps1 = VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKeyNew)
    result, _ = PublishedDeterministicTaggingCheckProof(PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: libunlynx.SuiTe.Point().Mul(secKeyNew, libunlynx.SuiTe.Point().Base())})
    assert.False(t, result)

    cps1 = VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKey)
    result, _ = PublishedDeterministicTaggingCheckProof(PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKeyNew, SB: libunlynx.SuiTe.Point().Mul(secKeyNew, libunlynx.SuiTe.Point().Base())})
    assert.False(t, result)

    cps1 = VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKey)
    result, _ = PublishedDeterministicTaggingCheckProof(PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: libunlynx.SuiTe.Point().Mul(secKey, libunlynx.SuiTe.Point().Base())})
    assert.False(t, result)
}
