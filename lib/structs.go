// Package libmedco contains medco_structs which contains structures and methods built on basic structures defined in crypto
package lib

import (
	"strconv"
	"strings"

	"sync"

	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/cipher"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
)

//var mutexParallel sync.Mutex

// Objects
//______________________________________________________________________________________________________________________

// GroupingKey is an ID corresponding to grouping attributes.
type GroupingKey string

// TempID unique ID used in related maps which is used when we split a map in two associated maps.
type TempID uint64

// CipherVectorScalar contains the elements forming precomputed values for shuffling, a CipherVector and the scalars
// corresponding to each element
type CipherVectorScalar struct {
	CipherV CipherVector
	S       []abstract.Scalar
}

// CipherVectorScalarBytes is a CipherVectorScalar in bytes
type CipherVectorScalarBytes struct {
	CipherV [][][]byte
	S       [][]byte
}

// ClientResponse represents a client response.
type ClientResponse struct {
	GroupingAttributesClear    GroupingKey
	ProbaGroupingAttributesEnc CipherVector
	AggregatingAttributes      CipherVector
}

// ClientResponseBytes represents a client response in bytes.
type ClientResponseBytes struct {
	GroupingAttributesClear    []byte
	ProbaGroupingAttributesEnc [][][]byte
	AggregatingAttributes      [][][]byte
}

// ClientClearResponse represents a client response when data is stored in clear at each server/hospital
type ClientClearResponse struct {
	GroupingAttributesClear []int64
	GroupingAttributesEnc   []int64
	AggregatingAttributes   []int64
}

// ClientResponseDetCreation represents a client response which is in the process of creating a det. hash
type ClientResponseDetCreation struct {
	CR          ClientResponse
	DetCreaVect CipherVector
}

// ClientResponseDet represents a client response associated to a det. hash
type ClientResponseDet struct {
	CR     ClientResponse
	DetTag GroupingKey
}

// SurveyID unique ID for each survey.
type SurveyID string

// Survey represents a survey with the corresponding params where PH key is different for each server.
type Survey struct {
	*Store
	GenID              SurveyID
	ID                 SurveyID
	Roster             onet.Roster
	SurveySecretKey    abstract.Scalar
	ClientPublic       abstract.Point
	SurveyDescription  SurveyDescription
	Proofs             bool
	ShufflePrecompute  []CipherVectorScalar
	SurveyQuerySubject []ClientResponse
	DataToProcess      []ClientResponse
	NbrDPs             map[string]int64
	ExecutionMode      int64
	SurveyResponses    []ClientResponse
	Sender             network.ServerIdentityID
	Final              bool
}

// SurveyDescription is currently only used to define a client response format.
type SurveyDescription struct {
	GroupingAttributesClearCount int32
	GroupingAttributesEncCount   int32
	AggregatingAttributesCount   uint32
}

// Functions
//______________________________________________________________________________________________________________________

// NewClientResponse creates a new client response with chosen grouping and aggregating number of attributes
func NewClientResponse(grpEncSize, attrSize int) ClientResponse {
	return ClientResponse{"", *NewCipherVector(grpEncSize), *NewCipherVector(attrSize)}
}

// NewClientClearResponse creates a new client response with chosen grouping and aggregating number of attributes
func NewClientClearResponse(grpSizeClear, grpSizeEnc, attrSize int) ClientClearResponse {
	return ClientClearResponse{make([]int64, grpSizeClear), make([]int64, grpSizeEnc), make([]int64, attrSize)}
}

// GroupingKey
//______________________________________________________________________________________________________________________

// Key allows to transform non-encrypted grouping attributes to a tag (groupingkey)
func Key(ga []int64) GroupingKey {
	var key []string
	for _, a := range ga {
		key = append(key, strconv.Itoa(int(a)))
		key = append(key, ",")
	}
	return GroupingKey(strings.Join(key, ""))
}

// UnKey permits to go from a tag  non-encrypted grouping attributes to grouping attributes
func UnKey(gk GroupingKey) []int64 {
	tab := make([]int64, 0)
	count := 0
	nbrString := make([]string, 1)
	for _, a := range gk {
		if a != ',' {
			nbrString[0] = string(a)
		} else {
			tmp, _ := strconv.Atoi(strings.Join(nbrString, ""))
			tab = append(tab, int64(tmp))
			nbrString = make([]string, 1)
			count++
		}
	}
	return tab
}

// ClientResponse
//______________________________________________________________________________________________________________________

// Add two client responses and stores result in receiver.
func (cv *ClientResponse) Add(cv1, cv2 ClientResponse) *ClientResponse {
	cv.GroupingAttributesClear = cv1.GroupingAttributesClear
	cv.ProbaGroupingAttributesEnc = cv1.ProbaGroupingAttributesEnc
	cv.AggregatingAttributes.Add(cv1.AggregatingAttributes, cv2.AggregatingAttributes)
	return cv
}

// CipherVectorTag computes all the e for a client responses based on a seed h
func (cv *ClientResponse) CipherVectorTag(h abstract.Point) []abstract.Scalar {
	aggrAttrLen := len((*cv).AggregatingAttributes)
	grpAttrLen := len((*cv).ProbaGroupingAttributesEnc)
	es := make([]abstract.Scalar, aggrAttrLen+grpAttrLen)

	seed, _ := h.MarshalBinary()
	var wg sync.WaitGroup
	if PARALLELIZE {
		for i := 0; i < aggrAttrLen+grpAttrLen; i = i + VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				for j := 0; j < VPARALLELIZE && (j+i < aggrAttrLen+grpAttrLen); j++ {
					es[i+j] = ComputeE(i+j, (*cv), seed, aggrAttrLen)
				}

			}(i)

		}
		wg.Wait()
	} else {
		for i := 0; i < aggrAttrLen+grpAttrLen; i++ {
			//+detAttrLen
			es[i] = ComputeE(i, (*cv), seed, aggrAttrLen)
		}

	}
	return es
}

// ComputeE computes e used in a shuffle proof. Computation based on a public seed.
func ComputeE(index int, cv ClientResponse, seed []byte, aggrAttrLen int) abstract.Scalar {
	var dataC []byte
	var dataK []byte

	randomCipher := network.Suite.Cipher(seed)

	if index < aggrAttrLen {
		dataC, _ = cv.AggregatingAttributes[index].C.MarshalBinary()
		dataK, _ = cv.AggregatingAttributes[index].K.MarshalBinary()

	} else /*if i < aggrAttrLen+grpAttrLen*/ {
		dataC, _ = cv.ProbaGroupingAttributesEnc[index-aggrAttrLen].C.MarshalBinary()
		dataK, _ = cv.ProbaGroupingAttributesEnc[index-aggrAttrLen].K.MarshalBinary()
	}
	randomCipher.Message(nil, nil, dataC)
	randomCipher.Message(nil, nil, dataK)

	return network.Suite.Scalar().Pick(randomCipher)
}

// ClientClearResponse
//______________________________________________________________________________________________________________________

// EncryptClientClearResponse encrypts a client response
func EncryptClientClearResponse(ccr ClientClearResponse, encryptionKey abstract.Point) ClientResponse {
	cr := ClientResponse{}
	cr.GroupingAttributesClear = Key(ccr.GroupingAttributesClear)
	cr.ProbaGroupingAttributesEnc = *EncryptIntVector(encryptionKey, ccr.GroupingAttributesEnc)
	cr.AggregatingAttributes = *EncryptIntVector(encryptionKey, ccr.AggregatingAttributes)

	return cr
}

// Other random stuff!! :P
//______________________________________________________________________________________________________________________

// CreatePrecomputedRandomize creates precomputed values for shuffling using public key and size parameters
func CreatePrecomputedRandomize(g, h abstract.Point, rand cipher.Stream, lineSize, nbrLines int) []CipherVectorScalar {
	result := make([]CipherVectorScalar, nbrLines)
	wg := StartParallelize(len(result))
	for i := range result {
		result[i].CipherV = make(CipherVector, lineSize)
		result[i].S = make([]abstract.Scalar, lineSize)
		if PARALLELIZE {
			go func(i int) {
				defer (*wg).Done()
				//mutexParallel.Lock()
				for w := range result[i].CipherV {
					tmp := network.Suite.Scalar().Pick(rand)
					result[i].S[w] = tmp
					result[i].CipherV[w].K = network.Suite.Point().Mul(g, tmp)
					result[i].CipherV[w].C = network.Suite.Point().Mul(h, tmp)
				}
				//mutexParallel.Unlock()
			}(i)
		} else {
			for w := range result[i].CipherV {
				tmp := network.Suite.Scalar().Pick(rand)
				result[i].S[w] = tmp
				result[i].CipherV[w].K = network.Suite.Point().Mul(g, tmp)
				result[i].CipherV[w].C = network.Suite.Point().Mul(h, tmp)
			}
		}
	}
	EndParallelize(wg)
	return result
}

// Conversion
//______________________________________________________________________________________________________________________

// ToBytes converts a ClientResponse to a byte array
func (cv *ClientResponse) ToBytes() ([]byte, int, int, int) {
	b := make([]byte, 0)
	pgaeb := make([]byte, 0)
	pgaebLength := 0

	gacb := []byte((*cv).GroupingAttributesClear)
	gacbLength := len(gacb)

	aab, aabLength := (*cv).AggregatingAttributes.ToBytes()
	if (*cv).ProbaGroupingAttributesEnc != nil {
		pgaeb, pgaebLength = (*cv).ProbaGroupingAttributesEnc.ToBytes()
	}

	b = append(b, gacb...)
	b = append(b, aab...)
	b = append(b, pgaeb...)

	return b, gacbLength, aabLength, pgaebLength
}

// FromBytes converts a byte array to a ClientResponse. Note that you need to create the (empty) object beforehand.
func (cv *ClientResponse) FromBytes(data []byte, gacbLength, aabLength, pgaebLength int) {
	(*cv).AggregatingAttributes = make(CipherVector, aabLength)
	(*cv).ProbaGroupingAttributesEnc = make(CipherVector, pgaebLength)

	aabByteLength := (aabLength * 64) //CAREFUL: hardcoded 64 (size of el-gamal element C,K)
	pgaebByteLength := (pgaebLength * 64)

	gacb := data[:gacbLength]
	aab := data[gacbLength : gacbLength+aabByteLength]
	pgaeb := data[gacbLength+aabByteLength : gacbLength+aabByteLength+pgaebByteLength]

	(*cv).GroupingAttributesClear = GroupingKey(string(gacb))
	(*cv).AggregatingAttributes.FromBytes(aab, aabLength)
	(*cv).ProbaGroupingAttributesEnc.FromBytes(pgaeb, pgaebLength)
}

// ToBytes converts a ClientResponseDet to a byte array
func (crd *ClientResponseDet) ToBytes() ([]byte, int, int, int, int) {
	b, gacbLength, aabLength, pgaebLength := (*crd).CR.ToBytes()

	dtb := []byte((*crd).DetTag)
	dtbLength := len(dtb)

	b = append(b, dtb...)

	return b, gacbLength, aabLength, pgaebLength, dtbLength
}

// FromBytes converts a byte array to a ClientResponseDet. Note that you need to create the (empty) object beforehand.
func (crd *ClientResponseDet) FromBytes(data []byte, gacbLength, aabLength, pgaebLength, dtbLength int) {
	(*crd).CR.AggregatingAttributes = make(CipherVector, aabLength)
	(*crd).CR.ProbaGroupingAttributesEnc = make(CipherVector, pgaebLength)

	aabByteLength := (aabLength * 64) //CAREFUL: hardcoded 64 (size of el-gamal element C,K)
	pgaebByteLength := (pgaebLength * 64)

	gacb := data[:gacbLength]
	aab := data[gacbLength : gacbLength+aabByteLength]
	pgaeb := data[gacbLength+aabByteLength : gacbLength+aabByteLength+pgaebByteLength]
	dtb := data[gacbLength+aabByteLength+pgaebByteLength : gacbLength+aabByteLength+pgaebByteLength+dtbLength]

	(*crd).DetTag = GroupingKey(string(dtb))
	(*crd).CR.GroupingAttributesClear = GroupingKey(string(gacb))
	(*crd).CR.AggregatingAttributes.FromBytes(aab, aabLength)
	(*crd).CR.ProbaGroupingAttributesEnc.FromBytes(pgaeb, pgaebLength)

}
