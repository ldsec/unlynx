package proofs_test

import (
    "testing"
    "github.com/lca1/unlynx/lib"
    "github.com/lca1/unlynx/lib/proofs"
    "github.com/stretchr/testify/assert"
)

func TestShufflingProof(t *testing.T) {
    tab1 := []int64{1, 2, 3, 6}
    testCipherVect1 := *libunlynx.EncryptIntVector(pubKey, tab1)

    tab2 := []int64{2, 4, 8, 6}
    testCipherVect2 := *libunlynx.EncryptIntVector(pubKey, tab2)

    responses := make([]libunlynx.ProcessResponse, 3)
    responses[0] = libunlynx.ProcessResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect2}
    responses[1] = libunlynx.ProcessResponse{GroupByEnc: testCipherVect1, AggregatingAttributes: testCipherVect1}
    responses[2] = libunlynx.ProcessResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect1}

    responsesShuffled, pi, beta := libunlynx.ShuffleSequence(responses, nil, pubKey, nil)
    PublishedShufflingProof := proofs.ShufflingProofCreation(responses, responsesShuffled, nil, pubKey, beta, pi)
    assert.True(t, proofs.ShufflingProofVerification(PublishedShufflingProof, pubKey))

    PublishedShufflingProof = proofs.ShufflingProofCreation(responses, responses, nil, pubKey, beta, pi)
    assert.False(t, proofs.ShufflingProofVerification(PublishedShufflingProof, pubKey))
}
