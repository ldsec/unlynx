package libunlynxaggr

import (
	"math"
	"sync"

	"github.com/lca1/unlynx/lib"
)

// PublishedAggregationProof contains all the information for one aggregation proof
type PublishedAggregationProof struct {
	Data              libunlynx.CipherVector
	AggregationResult libunlynx.CipherText
}

// PublishedAggregationProofBytes is the 'bytes' equivalent of PublishedAggregationProof
type PublishedAggregationProofBytes struct {
	Data              []byte
	DataLen           int64
	AggregationResult []byte
}

// PublishedAggregationListProof contains a list of aggregation proofs
type PublishedAggregationListProof struct {
	List []PublishedAggregationProof
}

// PublishedAggregationListProofBytes is the 'bytes' equivalent of PublishedAggregationListProof
type PublishedAggregationListProofBytes struct {
	List []PublishedAggregationProofBytes
}

// AGGREGATION proofs
//______________________________________________________________________________________________________________________

// AggregationProofCreation creates a proof for aggregation
func AggregationProofCreation(data libunlynx.CipherVector, aggregationResult libunlynx.CipherText) PublishedAggregationProof {
	return PublishedAggregationProof{Data: data, AggregationResult: aggregationResult}
}

// AggregationListProofCreation creates multiple proofs for aggregation
func AggregationListProofCreation(data []libunlynx.CipherVector, aggregationResults []libunlynx.CipherText) PublishedAggregationListProof {
	papList := PublishedAggregationListProof{}
	papList.List = make([]PublishedAggregationProof, len(data))

	var wg sync.WaitGroup
	for i := 0; i < len(data); i += libunlynx.VPARALLELIZE {
		wg.Add(1)
		go func(i int) {
			for j := 0; j < libunlynx.VPARALLELIZE && (i+j) < len(data); j++ {
				pap := AggregationProofCreation(data[i+j], aggregationResults[i+j])
				papList.List[i+j] = pap
			}
			defer wg.Done()
		}(i)
	}
	wg.Wait()

	return papList
}

// AggregationProofVerification verifies an aggregation proof
func AggregationProofVerification(pap PublishedAggregationProof) bool {
	expected := pap.Data.Acum()
	return expected.Equal(&pap.AggregationResult)
}

// AggregationListProofVerification verifies multiple aggregation proofs
func AggregationListProofVerification(palp PublishedAggregationListProof, percent float64) bool {
	nbrProofsToVerify := int(math.Ceil(percent * float64(len(palp.List))))
	results := make([]bool, nbrProofsToVerify)

	var wg sync.WaitGroup
	for i := 0; i < nbrProofsToVerify; i += libunlynx.VPARALLELIZE {
		wg.Add(1)
		go func(i int) {
			for j := 0; j < libunlynx.VPARALLELIZE && (i+j) < nbrProofsToVerify; j++ {
				results[i+j] = AggregationProofVerification(palp.List[i+j])
			}
			defer wg.Done()
		}(i)
	}
	wg.Wait()

	finalResult := true
	for _, v := range results {
		finalResult = finalResult && v
	}
	return finalResult
}

// Marshal
//______________________________________________________________________________________________________________________

// ToBytes converts PublishedAggregationProof to bytes
func (pap *PublishedAggregationProof) ToBytes() PublishedAggregationProofBytes {
	papb := PublishedAggregationProofBytes{}
	var dataLen int
	papb.Data, dataLen = pap.Data.ToBytes()
	papb.DataLen = int64(dataLen)
	papb.AggregationResult = pap.AggregationResult.ToBytes()
	return papb
}

// FromBytes converts back bytes to PublishedAggregationProof
func (pap *PublishedAggregationProof) FromBytes(papb PublishedAggregationProofBytes) {
	pap.AggregationResult.FromBytes(papb.AggregationResult)
	pap.Data.FromBytes(papb.Data, int(papb.DataLen))
}

// ToBytes converts PublishedAggregationListProof to bytes
func (palp *PublishedAggregationListProof) ToBytes() PublishedAggregationListProofBytes {
	palpb := PublishedAggregationListProofBytes{}

	palpb.List = make([]PublishedAggregationProofBytes, len(palp.List))
	wg := libunlynx.StartParallelize(len(palpb.List))
	for i, pap := range palp.List {
		go func(index int, pap PublishedAggregationProof) {
			defer wg.Done()
			palpb.List[index] = pap.ToBytes()
		}(i, pap)
	}
	libunlynx.EndParallelize(wg)
	return palpb
}

// FromBytes converts bytes back to PublishedAggregationListProof
func (palp *PublishedAggregationListProof) FromBytes(palpb PublishedAggregationListProofBytes) {
	palp.List = make([]PublishedAggregationProof, len(palpb.List))
	wg := libunlynx.StartParallelize(len(palpb.List))
	for i, papb := range palpb.List {
		go func(index int, papb PublishedAggregationProofBytes) {
			defer wg.Done()
			tmp := PublishedAggregationProof{}
			tmp.FromBytes(papb)
			palp.List[index] = tmp
		}(i, papb)
	}
	libunlynx.EndParallelize(wg)
}
