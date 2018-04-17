package libunlynxproofs_test

import (
    "github.com/lca1/unlynx/lib"
    "github.com/lca1/unlynx/lib/proofs"
    "github.com/stretchr/testify/assert"
    "testing"
)

func TestCollectiveAggregationProof(t *testing.T) {
    tab1 := []int64{1, 2, 3, 6}
    testCipherVect1 := *libunlynx.EncryptIntVector(pubKey, tab1)

    tab2 := []int64{2, 4, 8, 6}
    testCipherVect2 := *libunlynx.EncryptIntVector(pubKey, tab2)

    det1 := testCipherVect2
    det2 := testCipherVect1
    det3 := testCipherVect2

    det1.TaggingDet(secKey, secKey, pubKey, true)
    deterministicGroupAttributes := make(libunlynx.DeterministCipherVector, len(det1))
    for j, c := range det1 {
        deterministicGroupAttributes[j] = libunlynx.DeterministCipherText{Point: c.C}
    }
    newDetResponse1 := libunlynx.FilteredResponseDet{Fr: libunlynx.FilteredResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect1}, DetTagGroupBy: deterministicGroupAttributes.Key()}

    det2.TaggingDet(secKey, secKey, pubKey, true)

    deterministicGroupAttributes = make(libunlynx.DeterministCipherVector, len(det2))
    for j, c := range det2 {
        deterministicGroupAttributes[j] = libunlynx.DeterministCipherText{Point: c.C}
    }
    newDetResponse2 := libunlynx.FilteredResponseDet{Fr: libunlynx.FilteredResponse{GroupByEnc: testCipherVect1, AggregatingAttributes: testCipherVect1}, DetTagGroupBy: deterministicGroupAttributes.Key()}

    det3.TaggingDet(secKey, secKey, pubKey, true)
    deterministicGroupAttributes = make(libunlynx.DeterministCipherVector, len(det3))
    for j, c := range det3 {
        deterministicGroupAttributes[j] = libunlynx.DeterministCipherText{Point: c.C}
    }
    newDetResponse3 := libunlynx.FilteredResponseDet{Fr: libunlynx.FilteredResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect1}, DetTagGroupBy: deterministicGroupAttributes.Key()}

    detResponses := make([]libunlynx.FilteredResponseDet, 3)
    detResponses[0] = newDetResponse1
    detResponses[1] = newDetResponse2
    detResponses[2] = newDetResponse3

    comparisonMap := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)
    for _, v := range detResponses {
        libunlynx.AddInMap(comparisonMap, v.DetTagGroupBy, v.Fr)
    }

    resultingMap := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)
    for i, v := range comparisonMap {
        libunlynx.AddInMap(resultingMap, i, v)
        libunlynx.AddInMap(resultingMap, i, v)
    }

    PublishedCollectiveAggregationProof := libunlynxproofs.CollectiveAggregationProofCreation(comparisonMap, detResponses, resultingMap)
    assert.True(t, libunlynxproofs.CollectiveAggregationProofVerification(PublishedCollectiveAggregationProof))

    PublishedCollectiveAggregationProof = libunlynxproofs.CollectiveAggregationProofCreation(resultingMap, detResponses, comparisonMap)
    assert.False(t, libunlynxproofs.CollectiveAggregationProofVerification(PublishedCollectiveAggregationProof))
}
