// Package libunlynx contains unlynx_structs which contains structures and methods built on basic structures defined in crypto
package libunlynx

import (
	"crypto/cipher"
	"encoding/binary"
	"strconv"
	"strings"
	"sync"

	"github.com/dedis/kyber"
)

// Objects
//______________________________________________________________________________________________________________________

// SEPARATOR is a string used in the transformation of some struct in []byte
const SEPARATOR = "/-/"

// GroupingKey is an ID corresponding to grouping attributes.
type GroupingKey string

// TempID unique ID used in related maps which is used when we split a map in two associated maps.
type TempID uint64

// CipherVectorScalar contains the elements forming precomputed values for shuffling, a CipherVector and the scalars
// corresponding to each element
type CipherVectorScalar struct {
	CipherV CipherVector
	S       []kyber.Scalar
}

// CipherVectorScalarBytes is a CipherVectorScalar in bytes
type CipherVectorScalarBytes struct {
	CipherV [][][]byte
	S       [][]byte
}

// DpClearResponse represents a DP response when data is stored in clear at each server/hospital
type DpClearResponse struct {
	WhereClear                 map[string]int64
	WhereEnc                   map[string]int64
	GroupByClear               map[string]int64
	GroupByEnc                 map[string]int64
	AggregatingAttributesClear map[string]int64
	AggregatingAttributesEnc   map[string]int64
}

// DpResponse represents an encrypted DP response (as it is sent to a server)
type DpResponse struct {
	WhereClear                 map[string]int64
	WhereEnc                   map[string]CipherText
	GroupByClear               map[string]int64
	GroupByEnc                 map[string]CipherText
	AggregatingAttributesClear map[string]int64
	AggregatingAttributesEnc   map[string]CipherText
}

// DpResponseToSend is a DpResponse formatted such that it can be sent with protobuf
type DpResponseToSend struct {
	WhereClear                 map[string]int64
	WhereEnc                   map[string][]byte
	GroupByClear               map[string]int64
	GroupByEnc                 map[string][]byte
	AggregatingAttributesClear map[string]int64
	AggregatingAttributesEnc   map[string][]byte
}

// ProcessResponse is a response in the format used for shuffling and det tag
type ProcessResponse struct {
	WhereEnc              CipherVector
	GroupByEnc            CipherVector
	AggregatingAttributes CipherVector
}

// WhereQueryAttribute is the name and encrypted value of a where attribute in the query
type WhereQueryAttribute struct {
	Name  string
	Value CipherText
}

// WhereQueryAttributeTagged is WhereQueryAttributes deterministically tagged
type WhereQueryAttributeTagged struct {
	Name  string
	Value GroupingKey
}

// ProcessResponseDet represents a DP response associated to a det. hash
type ProcessResponseDet struct {
	PR            ProcessResponse
	DetTagGroupBy GroupingKey
	DetTagWhere   []GroupingKey
}

// FilteredResponseDet is a FilteredResponse with its deterministic tag
type FilteredResponseDet struct {
	DetTagGroupBy GroupingKey
	Fr            FilteredResponse
}

// FilteredResponse is a response after the filtering step of the proto and until the end
type FilteredResponse struct {
	GroupByEnc            CipherVector
	AggregatingAttributes CipherVector
}

// Functions
//______________________________________________________________________________________________________________________

// NewFilteredResponse creates a new client response with chosen grouping and aggregating number of attributes
func NewFilteredResponse(grpEncSize, attrSize int) FilteredResponse {
	return FilteredResponse{*NewCipherVector(grpEncSize), *NewCipherVector(attrSize)}
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

// Add permits to add to FilteredResponses
func (cv *FilteredResponse) Add(cv1, cv2 FilteredResponse) *FilteredResponse {
	cv.GroupByEnc = cv1.GroupByEnc
	cv.AggregatingAttributes.Add(cv1.AggregatingAttributes, cv2.AggregatingAttributes)
	return cv
}

// CipherVectorTag computes all the e for a process response based on a seed h
func (cv *CipherVector) CipherVectorTag(h kyber.Point) []kyber.Scalar {
	length := len(*cv)
	es := make([]kyber.Scalar, length)

	seed, _ := h.MarshalBinary()
	var wg sync.WaitGroup

	for i := 0; i < length; i = i + VPARALLELIZE {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < VPARALLELIZE && (j+i < length); j++ {
				es[i+j] = ComputeE(i+j, *cv, seed)
			}

		}(i)

	}
	wg.Wait()

	return es
}

// ComputeE computes e used in a shuffle proof. Computation based on a public seed.
func ComputeE(index int, cv CipherVector, seed []byte) kyber.Scalar {
	var dataC []byte
	var dataK []byte

	randomCipher := SuiTe.XOF(seed)

	dataC, _ = cv[index].C.MarshalBinary()
	dataK, _ = cv[index].K.MarshalBinary()

	randomCipher.Write(dataC)
	randomCipher.Write(dataK)

	return SuiTe.Scalar().Pick(randomCipher)
}

// FormatAggregationProofs is used to format the data in a way that can be used to create aggregation proofs.
//		Example:
//			[
//			GroupingKey = "a"
//			Aggregating Attributes = [2, 3]
//
//			GroupingKey = "b"
//			Aggregating Attributes = [4, 7]
//
//			GroupingKey = "a"
//			Aggregating Attributes = [5, 1]
//			]
//
//		----> return value
//			[
//			GroupingKey = "a"
//			Data = [[2, 5], [3, 1]]
//
//			GroupingKey = "b"
//			Data = [[4], [7]]
//			]
func (crd *FilteredResponseDet) FormatAggregationProofs(res map[GroupingKey][]CipherVector) {
	if _, ok := res[crd.DetTagGroupBy]; ok {
		for i, ct := range crd.Fr.AggregatingAttributes {
			container := res[crd.DetTagGroupBy]
			container[i] = append(container[i], ct)
			res[crd.DetTagGroupBy] = container
		}
	} else { // if no elements are in the map yet
		container := make([]CipherVector, len(crd.Fr.AggregatingAttributes))
		for i, ct := range crd.Fr.AggregatingAttributes {
			tmp := make(CipherVector, 0)
			tmp = append(tmp, ct)
			container[i] = tmp
			res[crd.DetTagGroupBy] = container
		}
	}
}

// DpClearResponse
//______________________________________________________________________________________________________________________

// EncryptDpClearResponse encrypts a DP response
func EncryptDpClearResponse(ccr DpClearResponse, encryptionKey kyber.Point, count bool) DpResponseToSend {
	cr := DpResponseToSend{}
	cr.GroupByClear = ccr.GroupByClear
	cr.GroupByEnc = make(map[string][]byte, len(ccr.GroupByEnc))
	for i, v := range ccr.GroupByEnc {
		cr.GroupByEnc[i] = (*EncryptInt(encryptionKey, v)).ToBytes()
	}
	//cr.GroupByEnc = *EncryptIntVector(encryptionKey, ccr.GroupByEnc)
	cr.WhereClear = ccr.WhereClear
	cr.WhereEnc = make(map[string][]byte, len(ccr.WhereEnc))
	for i, v := range ccr.WhereEnc {
		cr.WhereEnc[i] = (*EncryptInt(encryptionKey, v)).ToBytes()
	}
	//cr.WhereEnc = *EncryptIntVector(encryptionKey, ccr.WhereEnc)
	cr.AggregatingAttributesClear = ccr.AggregatingAttributesClear
	cr.AggregatingAttributesEnc = make(map[string][]byte, len(ccr.AggregatingAttributesEnc))
	for i, v := range ccr.AggregatingAttributesEnc {
		cr.AggregatingAttributesEnc[i] = (*EncryptInt(encryptionKey, v)).ToBytes()
	}
	if count {
		cr.AggregatingAttributesEnc["count"] = (*EncryptInt(encryptionKey, int64(1))).ToBytes()
	}

	return cr
}

// Other random stuff!! :P
//______________________________________________________________________________________________________________________

// CreatePrecomputedRandomize creates precomputed values for shuffling using public key and size parameters
func CreatePrecomputedRandomize(g, h kyber.Point, rand cipher.Stream, lineSize, nbrLines int) []CipherVectorScalar {
	result := make([]CipherVectorScalar, nbrLines)
	wg := StartParallelize(len(result))
	var mutex sync.Mutex
	for i := range result {
		result[i].CipherV = make(CipherVector, lineSize)
		result[i].S = make([]kyber.Scalar, lineSize)

		go func(i int) {
			defer (*wg).Done()

			for w := range result[i].CipherV {
				mutex.Lock()
				tmp := SuiTe.Scalar().Pick(rand)
				mutex.Unlock()

				result[i].S[w] = tmp
				result[i].CipherV[w].K = SuiTe.Point().Mul(tmp, g)
				result[i].CipherV[w].C = SuiTe.Point().Mul(tmp, h)
			}

		}(i)
	}
	EndParallelize(wg)
	return result
}

// Conversion
//______________________________________________________________________________________________________________________

// ToBytes converts a Filtered to a byte array
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

// FromBytes converts a byte array to a FilteredResponse. Note that you need to create the (empty) object beforehand.
func (cv *FilteredResponse) FromBytes(data []byte, aabLength, pgaebLength int) {
	(*cv).AggregatingAttributes = make(CipherVector, aabLength)
	(*cv).GroupByEnc = make(CipherVector, pgaebLength)

	lengthCipher := 2 * SuiTe.PointLen()
	aabByteLength := aabLength * lengthCipher
	pgaebByteLength := pgaebLength * lengthCipher

	aab := data[:aabByteLength]
	pgaeb := data[aabByteLength : aabByteLength+pgaebByteLength]

	(*cv).AggregatingAttributes.FromBytes(aab, aabLength)
	(*cv).GroupByEnc.FromBytes(pgaeb, pgaebLength)
}

// ToBytes converts a FilteredResponseDet to a byte array
func (crd *FilteredResponseDet) ToBytes() ([]byte, int, int, int) {
	b, gacbLength, aabLength := (*crd).Fr.ToBytes()

	dtbgb := []byte((*crd).DetTagGroupBy)
	dtbgbLength := len(dtbgb)

	b = append(b, dtbgb...)

	return b, gacbLength, aabLength, dtbgbLength
}

// FromBytes converts a byte array to a FilteredResponseDet. Note that you need to create the (empty) object beforehand.
func (crd *FilteredResponseDet) FromBytes(data []byte, gacbLength, aabLength, dtbgbLength int) {
	(*crd).Fr.AggregatingAttributes = make(CipherVector, aabLength)
	(*crd).Fr.GroupByEnc = make(CipherVector, gacbLength)

	lengthCipher := 2 * SuiTe.PointLen()
	aabByteLength := aabLength * lengthCipher //CAREFUL: hardcoded 64 (size of el-gamal element C,K)
	gacbByteLength := gacbLength * lengthCipher

	aab := data[:aabByteLength]
	gacb := data[aabByteLength : gacbByteLength+aabByteLength]
	dtbgb := data[gacbByteLength+aabByteLength : gacbByteLength+aabByteLength+dtbgbLength]

	(*crd).DetTagGroupBy = GroupingKey(string(dtbgb))
	(*crd).Fr.AggregatingAttributes.FromBytes(aab, aabLength)
	(*crd).Fr.GroupByEnc.FromBytes(gacb, gacbLength)
}

// ToBytes converts a ProcessResponse to a byte array
func (cv *ProcessResponse) ToBytes() ([]byte, int, int, int) {
	b := make([]byte, 0)
	pgaeb := make([]byte, 0)
	pgaebLength := 0

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

// FromBytes converts a byte array to a ProcessResponse. Note that you need to create the (empty) object beforehand.
func (cv *ProcessResponse) FromBytes(data []byte, gacbLength, aabLength, pgaebLength int) {
	(*cv).AggregatingAttributes = make(CipherVector, aabLength)
	(*cv).WhereEnc = make(CipherVector, pgaebLength)
	(*cv).GroupByEnc = make(CipherVector, gacbLength)

	cipherTextByteSize := CipherTextByteSize()
	gacbByteLength := gacbLength * cipherTextByteSize
	aabByteLength := aabLength * cipherTextByteSize
	pgaebByteLength := pgaebLength * cipherTextByteSize

	gacb := data[:gacbByteLength]
	aab := data[gacbByteLength : gacbByteLength+aabByteLength]
	pgaeb := data[gacbByteLength+aabByteLength : gacbByteLength+aabByteLength+pgaebByteLength]

	(*cv).GroupByEnc.FromBytes(gacb, gacbLength)
	(*cv).AggregatingAttributes.FromBytes(aab, aabLength)
	(*cv).WhereEnc.FromBytes(pgaeb, pgaebLength)
}

// ToBytes converts a ProcessResponseDet to a byte array
func (crd *ProcessResponseDet) ToBytes() ([]byte, int, int, int, int, int) {
	b, gacbLength, aabLength, pgaebLength := (*crd).PR.ToBytes()

	dtbgb := []byte((*crd).DetTagGroupBy)
	dtbgbLength := len(dtbgb)
	strs := make([]string, len((*crd).DetTagWhere))
	for i, v := range (*crd).DetTagWhere {
		strs[i] = string(v)
	}
	dtbw := []byte(strings.Join(strs, SEPARATOR))
	dtbwLength := len(dtbw)

	b = append(b, dtbgb...)
	b = append(b, dtbw...)
	return b, gacbLength, aabLength, pgaebLength, dtbgbLength, dtbwLength
}

// FromBytes converts a byte array to a ProcessResponseDet. Note that you need to create the (empty) object beforehand.
func (crd *ProcessResponseDet) FromBytes(data []byte, gacbLength, aabLength, pgaebLength, dtbgbLength, dtbwLength int) {
	(*crd).PR.AggregatingAttributes = make(CipherVector, aabLength)
	(*crd).PR.WhereEnc = make(CipherVector, pgaebLength)
	(*crd).PR.GroupByEnc = make(CipherVector, gacbLength)

	cipherTextByteSize := CipherTextByteSize()
	aabByteLength := aabLength * cipherTextByteSize
	pgaebByteLength := pgaebLength * cipherTextByteSize
	gacbByteLength := gacbLength * cipherTextByteSize

	gacb := data[:gacbByteLength]
	aab := data[gacbByteLength : gacbByteLength+aabByteLength]
	pgaeb := data[gacbByteLength+aabByteLength : gacbByteLength+aabByteLength+pgaebByteLength]
	dtbgb := data[gacbByteLength+aabByteLength+pgaebByteLength : gacbByteLength+aabByteLength+pgaebByteLength+dtbgbLength]
	dtbw := data[gacbByteLength+aabByteLength+pgaebByteLength+dtbgbLength : gacbByteLength+aabByteLength+pgaebByteLength+dtbgbLength+dtbgbLength+dtbwLength]

	(*crd).DetTagGroupBy = GroupingKey(string(dtbgb))
	(*crd).DetTagWhere = make([]GroupingKey, 0)
	for _, key := range strings.Split(string(dtbw), SEPARATOR) {
		(*crd).DetTagWhere = append((*crd).DetTagWhere, GroupingKey(key))
	}
	(*crd).PR.AggregatingAttributes.FromBytes(aab, aabLength)
	(*crd).PR.WhereEnc.FromBytes(pgaeb, pgaebLength)
	(*crd).PR.GroupByEnc.FromBytes(gacb, gacbLength)

}

// FromDpResponseToSend converts a DpResponseToSend to a DpResponse
func (dr *DpResponse) FromDpResponseToSend(dprts DpResponseToSend) {
	dr.GroupByClear = dprts.GroupByClear
	if len(dprts.GroupByEnc) != 0 {
		dr.GroupByEnc = MapBytesToMapCipherText(dprts.GroupByEnc)
	}

	dr.WhereClear = dprts.WhereClear
	if len(dprts.WhereEnc) != 0 {
		dr.WhereEnc = make(map[string]CipherText)
		for i, v := range dprts.WhereEnc {
			ct := CipherText{}
			ct.FromBytes(v)
			dr.WhereEnc[i] = ct
		}
	}
	dr.AggregatingAttributesClear = dprts.AggregatingAttributesClear
	if len(dprts.AggregatingAttributesEnc) != 0 {
		dr.AggregatingAttributesEnc = make(map[string]CipherText)
		for i, v := range dprts.AggregatingAttributesEnc {
			ct := CipherText{}
			ct.FromBytes(v)
			dr.AggregatingAttributesEnc[i] = ct
		}
	}
}

// MapBytesToMapCipherText transform objects in a map from bytes to ciphertexts
func MapBytesToMapCipherText(mapBytes map[string][]byte) map[string]CipherText {
	result := make(map[string]CipherText)
	if len(mapBytes) != 0 {
		for i, v := range mapBytes {
			ct := CipherText{}
			ct.FromBytes(v)
			result[i] = ct
		}
		return result
	}

	return nil
}

// UnsafeCastIntsToBytes casts a slice of ints to a slice of bytes
func UnsafeCastIntsToBytes(ints []int) []byte {
	bsFinal := make([]byte, 0)
	for _, num := range ints {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(num))
		bsFinal = append(bsFinal, buf...)
	}
	return bsFinal
}

// UnsafeCastBytesToInts casts a slice of bytes to a slice of ints
func UnsafeCastBytesToInts(bytes []byte) []int {
	intsFinal := make([]int, 0)
	for i := 0; i < len(bytes); i += 4 {
		x := binary.BigEndian.Uint32(bytes[i : i+4])
		intsFinal = append(intsFinal, int(x))
	}
	return intsFinal
}
