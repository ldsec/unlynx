// Package lib contains medco_structs which contains structures and methods built on basic structures defined in crypto
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

type DpResponse struct {
	WhereClear            []int64
	WhereEnc              CipherVector
	GroupByClear          []int64
	GroupByEnc            CipherVector
	AggregatingAttributes CipherVector
}

type ProcessResponse struct {
	WhereEnc              CipherVector
	GroupByEnc            CipherVector
	AggregatingAttributes CipherVector
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
type DpClearResponse struct {
	WhereClear            []int64
	WhereEnc              []int64
	GroupByClear          []int64
	GroupByEnc            []int64
	AggregatingAttributes []int64
}

// ClientResponseDetCreation represents a client response which is in the process of creating a det. hash
type ClientResponseDetCreation struct {
	CR          ClientResponse
	DetCreaVect CipherVector
}

type WhereQueryAttribute struct {
	Name  string
	Value CipherText
}

type WhereQueryAttributeTagged struct {
	Name  string
	Value GroupingKey
}

// ClientResponseDet represents a client response associated to a det. hash
type ProcessResponseDet struct {
	CR            ProcessResponse
	DetTagGroupBy GroupingKey
	DetTagWhere   []GroupingKey
}

type FilteredResponseDet struct {
	DetTagGroupBy GroupingKey
	Fr            FilteredResponse
}

type FilteredResponse struct {
	GroupByEnc            CipherVector
	AggregatingAttributes CipherVector
}

// SurveyID unique ID for each survey.
type SurveyID string

/*type SurveyCreationQuery struct {
	SurveyGenID       *lib.SurveyID
	SurveyID          *lib.SurveyID
	Roster            onet.Roster
	//SurveyDescription lib.SurveyDescription
	Sum 		  []string
	Count 		  bool
	Where		  []lib.WhereQueryAttribute
	Pred 		  []string
	GroupBy		  []string
	//QuerySubject      []lib.ClientResponse
	ClientPubKey      abstract.Point
	DataToProcess     []lib.ClientResponse
	NbrDPs            map[string]int64
	QueryMode  	  int64
	Proofs            bool
	AppFlag           bool
}*/

type SurveyCreationQuery struct {
	SurveyGenID *SurveyID
	SurveyID    *SurveyID
	Roster      onet.Roster
	//SurveyDescription lib.SurveyDescription
	Sum     []string
	Count   bool
	Where   []WhereQueryAttribute
	Pred    string
	GroupBy []string
	//QuerySubject      []lib.ClientResponse
	ClientPubKey  abstract.Point
	DataToProcess []ClientResponse
	NbrDPs        map[string]int64
	QueryMode     int64
	Proofs        bool
	AppFlag       bool
}

// Survey represents a survey with the corresponding params
type Survey struct {
	*Store
	Query SurveyCreationQuery
	//GenID              SurveyID
	//ID                 SurveyID
	//Roster             onet.Roster
	SurveySecretKey abstract.Scalar
	//ClientPublic       abstract.Point
	//SurveyDescription  SurveyDescription
	//Proofs             bool
	ShufflePrecompute []CipherVectorScalar
	//SurveyQuerySubject []ClientResponse
	//DataToProcess      []ClientResponse
	//NbrDPs             map[string]int64
	//ExecutionMode      int64
	SurveyResponses []FilteredResponse
	Sender          network.ServerIdentityID
	Final           bool
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
func NewClientResponse(grpEncSize, attrSize int) FilteredResponse {
	return FilteredResponse{*NewCipherVector(grpEncSize), *NewCipherVector(attrSize)}
}

// NewClientClearResponse creates a new client response with chosen grouping and aggregating number of attributes
/*func NewClientClearResponse(grpSizeClear, grpSizeEnc, attrSize int) DpClearResponse {
	return DpClearResponse{make([]int64, grpSizeClear), make([]int64, grpSizeEnc), make([]int64, attrSize)}
}*/

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

func (cv *FilteredResponse) Add(cv1, cv2 FilteredResponse) *FilteredResponse {
	cv.GroupByEnc = cv1.GroupByEnc
	//cv.ProbaGroupingAttributesEnc = cv1.ProbaGroupingAttributesEnc
	cv.AggregatingAttributes.Add(cv1.AggregatingAttributes, cv2.AggregatingAttributes)
	return cv
}

// CipherVectorTag computes all the e for a client responses based on a seed h
func (cv *ProcessResponse) CipherVectorTag(h abstract.Point) []abstract.Scalar {
	aggrAttrLen := len((*cv).AggregatingAttributes)
	grpAttrLen := len((*cv).GroupByEnc)
	whereAttrLen := len((*cv).WhereEnc)
	es := make([]abstract.Scalar, aggrAttrLen+grpAttrLen+whereAttrLen)

	seed, _ := h.MarshalBinary()
	var wg sync.WaitGroup
	if PARALLELIZE {
		for i := 0; i < aggrAttrLen+grpAttrLen+whereAttrLen; i = i + VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				for j := 0; j < VPARALLELIZE && (j+i < aggrAttrLen+grpAttrLen+whereAttrLen); j++ {
					es[i+j] = ComputeE(i+j, (*cv), seed, aggrAttrLen, grpAttrLen)
				}

			}(i)

		}
		wg.Wait()
	} else {
		for i := 0; i < aggrAttrLen+grpAttrLen; i++ {
			//+detAttrLen
			es[i] = ComputeE(i, (*cv), seed, aggrAttrLen, grpAttrLen)
		}

	}
	return es
}

// ComputeE computes e used in a shuffle proof. Computation based on a public seed.
func ComputeE(index int, cv ProcessResponse, seed []byte, aggrAttrLen, grpAttrLen int) abstract.Scalar {
	var dataC []byte
	var dataK []byte

	randomCipher := network.Suite.Cipher(seed)

	if index < aggrAttrLen {
		dataC, _ = cv.AggregatingAttributes[index].C.MarshalBinary()
		dataK, _ = cv.AggregatingAttributes[index].K.MarshalBinary()

	} else if index < aggrAttrLen+grpAttrLen {
		dataC, _ = cv.GroupByEnc[index-aggrAttrLen].C.MarshalBinary()
		dataK, _ = cv.GroupByEnc[index-aggrAttrLen].K.MarshalBinary()
	} else {
		dataC, _ = cv.WhereEnc[index-aggrAttrLen-grpAttrLen].C.MarshalBinary()
		dataK, _ = cv.WhereEnc[index-aggrAttrLen-grpAttrLen].K.MarshalBinary()
	}
	randomCipher.Message(nil, nil, dataC)
	randomCipher.Message(nil, nil, dataK)

	return network.Suite.Scalar().Pick(randomCipher)
}

// ClientClearResponse
//______________________________________________________________________________________________________________________

// EncryptClientClearResponse encrypts a client response
func EncryptClientClearResponse(ccr DpClearResponse, encryptionKey abstract.Point) DpResponse {
	cr := DpResponse{}
	cr.GroupByClear = ccr.GroupByClear
	cr.GroupByEnc = *EncryptIntVector(encryptionKey, ccr.GroupByEnc)
	cr.WhereClear = ccr.WhereClear
	cr.WhereEnc = *EncryptIntVector(encryptionKey, ccr.WhereEnc)
	cr.AggregatingAttributes = *EncryptIntVector(encryptionKey, ccr.AggregatingAttributes)

	return cr
}

// Other random stuff!! :P
//______________________________________________________________________________________________________________________

// CreatePrecomputedRandomize creates precomputed values for shuffling using public key and size parameters
func CreatePrecomputedRandomize(g, h abstract.Point, rand cipher.Stream, lineSize, nbrLines int) []CipherVectorScalar {
	result := make([]CipherVectorScalar, nbrLines)
	wg := StartParallelize(len(result))
	var mutex sync.Mutex
	for i := range result {
		result[i].CipherV = make(CipherVector, lineSize)
		result[i].S = make([]abstract.Scalar, lineSize)
		if PARALLELIZE {
			go func(i int) {
				defer (*wg).Done()

				for w := range result[i].CipherV {
					mutex.Lock()
					tmp := network.Suite.Scalar().Pick(rand)
					mutex.Unlock()

					result[i].S[w] = tmp
					result[i].CipherV[w].K = network.Suite.Point().Mul(g, tmp)
					result[i].CipherV[w].C = network.Suite.Point().Mul(h, tmp)
				}

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

// ToBytes converts a ClientResponse to a byte array
func (cv *FilteredResponse) ToBytes() ([]byte, int, int) {
	b := make([]byte, 0)
	pgaeb := make([]byte, 0)
	pgaebLength := 0

	aab, aabLength := (*cv).AggregatingAttributes.ToBytes()
	if (*cv).GroupByEnc != nil {
		pgaeb, pgaebLength = (*cv).GroupByEnc.ToBytes()
	}

	b = append(b, aab...)
	b = append(b, pgaeb...)

	return b, pgaebLength, aabLength
}

// FromBytes converts a byte array to a ClientResponse. Note that you need to create the (empty) object beforehand.
func (cv *FilteredResponse) FromBytes(data []byte, aabLength, pgaebLength int) {
	(*cv).AggregatingAttributes = make(CipherVector, aabLength)
	(*cv).GroupByEnc = make(CipherVector, pgaebLength)

	aabByteLength := (aabLength * 64) //CAREFUL: hardcoded 64 (size of el-gamal element C,K)
	pgaebByteLength := (pgaebLength * 64)

	aab := data[:aabByteLength]
	pgaeb := data[aabByteLength : aabByteLength+pgaebByteLength]

	(*cv).AggregatingAttributes.FromBytes(aab, aabLength)
	(*cv).GroupByEnc.FromBytes(pgaeb, pgaebLength)
}

// ToBytes converts a ClientResponseDet to a byte array
func (crd *FilteredResponseDet) ToBytes() ([]byte, int, int, int) {
	b, gacbLength, aabLength := (*crd).Fr.ToBytes()

	dtbgb := []byte((*crd).DetTagGroupBy)
	dtbgbLength := len(dtbgb)

	b = append(b, dtbgb...)

	return b, gacbLength, aabLength, dtbgbLength
}

// FromBytes converts a byte array to a ClientResponseDet. Note that you need to create the (empty) object beforehand.
func (crd *FilteredResponseDet) FromBytes(data []byte, gacbLength, aabLength, dtbgbLength int) {
	(*crd).Fr.AggregatingAttributes = make(CipherVector, aabLength)
	(*crd).Fr.GroupByEnc = make(CipherVector, gacbLength)

	aabByteLength := (aabLength * 64) //CAREFUL: hardcoded 64 (size of el-gamal element C,K)
	gacbByteLength := (gacbLength * 64)

	aab := data[:aabByteLength]
	gacb := data[aabByteLength : gacbByteLength+aabByteLength]
	dtbgb := data[gacbByteLength+aabByteLength : gacbByteLength+aabByteLength+dtbgbLength]

	(*crd).DetTagGroupBy = GroupingKey(string(dtbgb))
	(*crd).Fr.AggregatingAttributes.FromBytes(aab, aabLength)
	(*crd).Fr.GroupByEnc.FromBytes(gacb, gacbLength)
}

// ToBytes converts a ClientResponse to a byte array
func (cv *ProcessResponse) ToBytes() ([]byte, int, int, int) {
	b := make([]byte, 0)
	pgaeb := make([]byte, 0)
	pgaebLength := 0

	//gacb := []byte((*cv).GroupingAttributesClear)
	//gacbLength := len(gacb)

	gacb, gacbLength := (*cv).GroupByEnc.ToBytes()
	aab, aabLength := (*cv).AggregatingAttributes.ToBytes()
	if (*cv).WhereEnc != nil {
		pgaeb, pgaebLength = (*cv).WhereEnc.ToBytes()
	}

	b = append(b, gacb...)
	b = append(b, aab...)
	b = append(b, pgaeb...)

	return b, gacbLength, aabLength, pgaebLength
}

// FromBytes converts a byte array to a ClientResponse. Note that you need to create the (empty) object beforehand.
func (cv *ProcessResponse) FromBytes(data []byte, gacbLength, aabLength, pgaebLength int) {
	(*cv).AggregatingAttributes = make(CipherVector, aabLength)
	(*cv).WhereEnc = make(CipherVector, pgaebLength)
	(*cv).GroupByEnc = make(CipherVector, gacbLength)

	gacbByteLength := (gacbLength * 64)
	aabByteLength := (aabLength * 64) //CAREFUL: hardcoded 64 (size of el-gamal element C,K)
	pgaebByteLength := (pgaebLength * 64)

	gacb := data[:gacbByteLength]
	aab := data[gacbByteLength : gacbByteLength+aabByteLength]
	pgaeb := data[gacbByteLength+aabByteLength : gacbByteLength+aabByteLength+pgaebByteLength]

	(*cv).GroupByEnc.FromBytes(gacb, gacbLength)
	(*cv).AggregatingAttributes.FromBytes(aab, aabLength)
	(*cv).WhereEnc.FromBytes(pgaeb, pgaebLength)
}

// ToBytes converts a ClientResponseDet to a byte array
func (crd *ProcessResponseDet) ToBytes() ([]byte, int, int, int, int, int) {
	b, gacbLength, aabLength, pgaebLength := (*crd).CR.ToBytes()

	dtbgb := []byte((*crd).DetTagGroupBy)
	dtbgbLength := len(dtbgb)
	dtbw := []byte((*crd).DetTagGroupBy)
	dtbwLength := len(dtbw)

	b = append(b, dtbgb...)
	b = append(b, dtbw...)
	return b, gacbLength, aabLength, pgaebLength, dtbgbLength, dtbwLength
}

// FromBytes converts a byte array to a ClientResponseDet. Note that you need to create the (empty) object beforehand.
func (crd *ProcessResponseDet) FromBytes(data []byte, gacbLength, aabLength, pgaebLength, dtbgbLength, dtbwLength int) {
	(*crd).CR.AggregatingAttributes = make(CipherVector, aabLength)
	(*crd).CR.WhereEnc = make(CipherVector, pgaebLength)
	(*crd).CR.GroupByEnc = make(CipherVector, gacbLength)

	aabByteLength := (aabLength * 64) //CAREFUL: hardcoded 64 (size of el-gamal element C,K)
	pgaebByteLength := (pgaebLength * 64)
	gacbByteLength := (gacbLength * 64)

	gacb := data[:gacbByteLength]
	aab := data[gacbByteLength : gacbByteLength+aabByteLength]
	pgaeb := data[gacbByteLength+aabByteLength : gacbByteLength+aabByteLength+pgaebByteLength]
	dtbgb := data[gacbByteLength+aabByteLength+pgaebByteLength : gacbByteLength+aabByteLength+pgaebByteLength+dtbgbLength]
	dtbw := data[gacbByteLength+aabByteLength+pgaebByteLength+dtbgbLength : gacbByteLength+aabByteLength+pgaebByteLength+dtbgbLength+dtbgbLength+dtbwLength]

	(*crd).DetTagGroupBy = GroupingKey(string(dtbgb))
	(*crd).DetTagGroupBy = GroupingKey(string(dtbw))
	(*crd).CR.AggregatingAttributes.FromBytes(aab, aabLength)
	(*crd).CR.WhereEnc.FromBytes(pgaeb, pgaebLength)
	(*crd).CR.GroupByEnc.FromBytes(gacb, gacbLength)

}
