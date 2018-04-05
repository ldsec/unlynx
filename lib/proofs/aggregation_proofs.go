package proofs

import (
    "reflect"
    "github.com/lca1/unlynx/lib"
)

// PublishedAggregationProof contains all infos about proofs for aggregation of two filtered responses
type PublishedAggregationProof struct {
    FilteredResponses  []libunlynx.FilteredResponseDet
    AggregationResults map[libunlynx.GroupingKey]libunlynx.FilteredResponse
}

// AggregationProofCreation creates a proof for responses aggregation and grouping
func AggregationProofCreation(responses []libunlynx.FilteredResponseDet, aggregatedResults map[libunlynx.GroupingKey]libunlynx.FilteredResponse) PublishedAggregationProof {
    return PublishedAggregationProof{FilteredResponses: responses, AggregationResults: aggregatedResults}
}

// AggregationProofVerification checks a proof for responses aggregation and grouping
func AggregationProofVerification(pap PublishedAggregationProof) bool {
    comparisonMap := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)
    for _, v := range pap.FilteredResponses {
        libunlynx.AddInMap(comparisonMap, v.DetTagGroupBy, v.Fr)
    }
    return reflect.DeepEqual(comparisonMap, pap.AggregationResults)
}