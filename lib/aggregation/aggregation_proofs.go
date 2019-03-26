package libunlynxaggr

import (
	"math"

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
	PapList []PublishedAggregationProof
}

// PublishedAggregationListProofBytes is the 'bytes' equivalent of PublishedAggregationListProof
type PublishedAggregationListProofBytes struct {
	PapList []PublishedAggregationProofBytes
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
	expected := pap.Data.Acum()
	return expected.Equal(&pap.AggregationResult)
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

// FromBytes converts back bytes to PublishedKSProof
func (pap *PublishedAggregationProof) FromBytes(papb PublishedAggregationProofBytes) {
	pap.AggregationResult.FromBytes(papb.AggregationResult)
	pap.Data.FromBytes(papb.Data, int(papb.DataLen))
}

// ToBytes converts PublishedAggregationListProof to bytes
func (palp *PublishedAggregationListProof) ToBytes() PublishedAggregationListProofBytes {
	palpb := PublishedAggregationListProofBytes{}

	palpb.PapList = make([]PublishedAggregationProofBytes, len(palp.PapList))
	wg := libunlynx.StartParallelize(len(palpb.PapList))
	for i, pap := range palp.PapList {
		go func(index int, pap PublishedAggregationProof) {
			defer wg.Done()
			palpb.PapList[index] = pap.ToBytes()
		}(i, pap)
	}
	libunlynx.EndParallelize(wg)
	return palpb
}

// FromBytes converts bytes back to PublishedAggregationListProof
func (palp *PublishedAggregationListProof) FromBytes(palpb PublishedAggregationListProofBytes) {
	palp.PapList = make([]PublishedAggregationProof, len(palpb.PapList))
	wg := libunlynx.StartParallelize(len(palpb.PapList))
	for i, papb := range palpb.PapList {
		go func(index int, papb PublishedAggregationProofBytes) {
			defer wg.Done()
			tmp := PublishedAggregationProof{}
			tmp.FromBytes(papb)
			palp.PapList[index] = tmp
		}(i, papb)
	}
	libunlynx.EndParallelize(wg)
}
