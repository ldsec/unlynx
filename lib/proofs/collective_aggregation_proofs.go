package libunlynxproofs

import (
    "github.com/lca1/unlynx/lib"
)
// PublishedCollectiveAggregationProof contains all infos about proofs for coll aggregation of filtered responses
type PublishedCollectiveAggregationProof struct {
    Aggregation1       map[libunlynx.GroupingKey]libunlynx.FilteredResponse
    Aggregation2       []libunlynx.FilteredResponseDet
    AggregationResults map[libunlynx.GroupingKey]libunlynx.FilteredResponse
}

// CollectiveAggregationProofCreation creates a proof for responses collective aggregation and grouping
func CollectiveAggregationProofCreation(aggregated1 map[libunlynx.GroupingKey]libunlynx.FilteredResponse, aggregated2 []libunlynx.FilteredResponseDet, aggregatedResults map[libunlynx.GroupingKey]libunlynx.FilteredResponse) PublishedCollectiveAggregationProof {
    return PublishedCollectiveAggregationProof{Aggregation1: aggregated1, Aggregation2: aggregated2, AggregationResults: aggregatedResults}
}

// CollectiveAggregationProofVerification checks a proof for responses collective aggregation and grouping
func CollectiveAggregationProofVerification(pcap PublishedCollectiveAggregationProof) bool {
    c1 := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)
    for i, v := range pcap.Aggregation1 {
        libunlynx.AddInMap(c1, i, v)
    }
    for _, v := range pcap.Aggregation2 {
        libunlynx.AddInMap(c1, v.DetTagGroupBy, v.Fr)
    }

    //compare maps
    result := true
    if len(c1) != len(pcap.AggregationResults) {
        result = false
    }
    for i, v := range c1 {
        for j, w := range v.AggregatingAttributes {
            if !w.C.Equal(pcap.AggregationResults[i].AggregatingAttributes[j].C) {
                result = false
            }
            if !w.K.Equal(pcap.AggregationResults[i].AggregatingAttributes[j].K) {
                result = false
            }
        }
        for j, w := range v.GroupByEnc {
            if !w.C.Equal(pcap.AggregationResults[i].GroupByEnc[j].C) {
                result = false
            }
            if !w.K.Equal(pcap.AggregationResults[i].GroupByEnc[j].K) {
                result = false
            }
        }

    }
    return result
}
