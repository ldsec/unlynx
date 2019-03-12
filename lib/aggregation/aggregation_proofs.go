package libunlynxaggr

import (
	"math"
	"reflect"

	"github.com/lca1/unlynx/lib"
)

// PublishedAggregationProof contains all the information for one aggregation proof
type PublishedAggregationProof struct {
	Data              libunlynx.CipherVector
	AggregationResult libunlynx.CipherText
}

// PublishedAggregationListProof contains a list of aggregation proofs
type PublishedAggregationListProof struct {
	PapList []PublishedAggregationProof
}

// AggregationProofCreation creates a proof for aggregation
func AggregationProofCreation(data libunlynx.CipherVector, aggregationResult libunlynx.CipherText) PublishedAggregationProof {
	return PublishedAggregationProof{Data: data, AggregationResult: aggregationResult}
}

// AggregationListProofCreation creates multiple proofs for aggregation
func AggregationListProofCreation(data []libunlynx.CipherVector, aggregationResults []libunlynx.CipherText) PublishedAggregationListProof {
	papList := PublishedAggregationListProof{}
	papList.PapList = make([]PublishedAggregationProof, 0)
	for i, v := range data {
		pap := AggregationProofCreation(v, aggregationResults[i])
		papList.PapList = append(papList.PapList, pap)
	}
	return papList
}

// AggregationProofVerification verifies an aggregation proof
func AggregationProofVerification(pap PublishedAggregationProof) bool {
	expected := pap.Data[0]
	for i := 1; i < len(pap.Data); i++ {
		expected.Add(expected, pap.Data[i])
	}
	return reflect.DeepEqual(expected, pap.AggregationResult)
}

// AggregationListProofVerification verifies multiple aggregation proofs
func AggregationListProofVerification(palp PublishedAggregationListProof, percent float64) bool {
	nbrProofsToVerify := int(math.Ceil(percent * float64(len(palp.PapList))))

	wg := libunlynx.StartParallelize(nbrProofsToVerify)
	results := make([]bool, nbrProofsToVerify)
	for i := 0; i < nbrProofsToVerify; i++ {
		go func(i int, v PublishedAggregationProof) {
			defer wg.Done()
			results[i] = AggregationProofVerification(v)
		}(i, palp.PapList[i])

	}
	libunlynx.EndParallelize(wg)
	finalResult := true
	for _, v := range results {
		finalResult = finalResult && v
	}
	return finalResult
}
