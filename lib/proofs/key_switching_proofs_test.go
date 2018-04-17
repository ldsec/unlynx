package libunlynxproofs_test

import (
    "testing"
    "github.com/lca1/unlynx/lib"
    "github.com/lca1/unlynx/lib/proofs"
    "github.com/stretchr/testify/assert"
    "github.com/dedis/kyber"
)

// TesKeySwitchingProof tests KEY SWITCHING
func TestKeySwitchingProof(t *testing.T) {
    //test key switching proofs at ciphertext level
    cipherOneSwitched := libunlynx.NewCipherText()
    r := cipherOneSwitched.KeySwitching(cipherOne, cipherOne.K, pubKeyNew, secKey)
    cp := libunlynxproofs.SwitchKeyProofCreation(cipherOne, *cipherOneSwitched, r, secKey, cipherOne.K, pubKeyNew)
    assert.True(t, libunlynxproofs.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, cipherOne, *cipherOneSwitched))

    aux := libunlynx.NewCipherText()
    aux.Add(cipherOne, cipherOne)
    assert.False(t, libunlynxproofs.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, *aux, *cipherOneSwitched))

    aux = libunlynx.NewCipherText()
    aux.Add(cipherOne, cipherOne)
    assert.False(t, libunlynxproofs.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, cipherOne, *aux))
    assert.False(t, libunlynxproofs.SwitchKeyCheckProof(cp, pubKey, pubKey, cipherOne, *cipherOneSwitched))
    assert.False(t, libunlynxproofs.SwitchKeyCheckProof(cp, pubKeyNew, pubKeyNew, cipherOne, *cipherOneSwitched))

    cp = libunlynxproofs.SwitchKeyProofCreation(cipherOne, *cipherOneSwitched, secKey, secKey, cipherOne.K, pubKeyNew)
    assert.False(t, libunlynxproofs.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, cipherOne, *cipherOneSwitched))

    cp = libunlynxproofs.SwitchKeyProofCreation(cipherOne, *cipherOneSwitched, r, r, cipherOne.K, pubKeyNew)
    assert.False(t, libunlynxproofs.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, cipherOne, *cipherOneSwitched))

    cp = libunlynxproofs.SwitchKeyProofCreation(cipherOne, *cipherOneSwitched, r, secKey, cipherOne.C, pubKeyNew)
    assert.False(t, libunlynxproofs.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, cipherOne, *cipherOneSwitched))

    cp = libunlynxproofs.SwitchKeyProofCreation(cipherOne, *cipherOneSwitched, r, secKey, cipherOne.K, libunlynx.SuiTe.Point().Add(pubKeyNew, pubKeyNew))
    assert.False(t, libunlynxproofs.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, cipherOne, *cipherOneSwitched))

    // test key switching at ciphervector level
    origEphemKeys := []kyber.Point{cipherOne.K, cipherOne.K}
    switchedVect := libunlynx.NewCipherVector(2)
    rs := switchedVect.KeySwitching(cipherVect, origEphemKeys, pubKeyNew, secKey)

    cps := libunlynxproofs.VectorSwitchKeyProofCreation(cipherVect, *switchedVect, rs, secKey, []kyber.Point{cipherOne.K, cipherOne.K}, pubKeyNew)
    assert.True(t, libunlynxproofs.PublishedSwitchKeyCheckProof(libunlynxproofs.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKey, Q: pubKeyNew}))

    assert.False(t, libunlynxproofs.PublishedSwitchKeyCheckProof(libunlynxproofs.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: cipherVect, K: pubKey, Q: pubKeyNew}))
    assert.False(t, libunlynxproofs.PublishedSwitchKeyCheckProof(libunlynxproofs.PublishedSwitchKeyProof{Skp: cps, VectBefore: *switchedVect, VectAfter: *switchedVect, K: pubKey, Q: pubKeyNew}))
    assert.False(t, libunlynxproofs.PublishedSwitchKeyCheckProof(libunlynxproofs.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKeyNew, Q: pubKeyNew}))
    assert.False(t, libunlynxproofs.PublishedSwitchKeyCheckProof(libunlynxproofs.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKey, Q: pubKey}))

    cps = libunlynxproofs.VectorSwitchKeyProofCreation(cipherVect, *switchedVect, rs, secKeyNew, []kyber.Point{cipherOne.K, cipherOne.K}, pubKeyNew)
    assert.False(t, libunlynxproofs.PublishedSwitchKeyCheckProof(libunlynxproofs.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKeyNew, Q: pubKeyNew}))

    cps = libunlynxproofs.VectorSwitchKeyProofCreation(cipherVect, *switchedVect, rs, secKey, []kyber.Point{cipherOne.K, cipherOne.K}, pubKey)
    assert.False(t, libunlynxproofs.PublishedSwitchKeyCheckProof(libunlynxproofs.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKeyNew, Q: pubKeyNew}))
}
