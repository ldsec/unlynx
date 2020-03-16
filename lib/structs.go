// Package libunlynx contains unlynx_structs which contains structures and methods built on basic structures defined in crypto
package libunlynx

import (
	"strconv"
	"strings"

	"go.dedis.ch/kyber/v3"
)

// Structs
//______________________________________________________________________________________________________________________

// SEPARATOR is a string used in the transformation of some struct in []byte
const SEPARATOR = "/-/"

// GroupingKey is an ID corresponding to grouping attributes.
type GroupingKey string

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

// Add permits to add to FilteredResponses
func (cv *FilteredResponse) Add(cv1, cv2 FilteredResponse) *FilteredResponse {
	cv.GroupByEnc = cv1.GroupByEnc
	cv.AggregatingAttributes.Add(cv1.AggregatingAttributes, cv2.AggregatingAttributes)
	return cv
}

// AddInMap permits to add a filtered response with its deterministic tag in a map
func AddInMap(s map[GroupingKey]FilteredResponse, key GroupingKey, added FilteredResponse) {
	if localResult, ok := s[key]; !ok {
		s[key] = added
	} else {
		nfr := NewFilteredResponse(len(added.GroupByEnc), len(added.AggregatingAttributes))
		s[key] = *nfr.Add(localResult, added)
	}
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
			cv := make(CipherVector, 0)
			cv = append(cv, ct)
			container[i] = cv
			res[crd.DetTagGroupBy] = container
		}
	}
}

// EncryptDpClearResponse encrypts a DP response
func EncryptDpClearResponse(ccr DpClearResponse, encryptionKey kyber.Point, count bool) (DpResponseToSend, error) {
	cr := DpResponseToSend{}
	cr.GroupByClear = ccr.GroupByClear
	cr.GroupByEnc = make(map[string][]byte, len(ccr.GroupByEnc))
	for i, v := range ccr.GroupByEnc {
		data, err := (*EncryptInt(encryptionKey, v)).ToBytes()
		if err != nil {
			return DpResponseToSend{}, err
		}
		cr.GroupByEnc[i] = data
	}
	//cr.GroupByEnc = *EncryptIntVector(encryptionKey, ccr.GroupByEnc)
	cr.WhereClear = ccr.WhereClear
	cr.WhereEnc = make(map[string][]byte, len(ccr.WhereEnc))
	for i, v := range ccr.WhereEnc {
		data, err := (*EncryptInt(encryptionKey, v)).ToBytes()
		if err != nil {
			return DpResponseToSend{}, err
		}
		cr.WhereEnc[i] = data
	}
	//cr.WhereEnc = *EncryptIntVector(encryptionKey, ccr.WhereEnc)
	cr.AggregatingAttributesClear = ccr.AggregatingAttributesClear
	cr.AggregatingAttributesEnc = make(map[string][]byte, len(ccr.AggregatingAttributesEnc))
	for i, v := range ccr.AggregatingAttributesEnc {
		data, err := (*EncryptInt(encryptionKey, v)).ToBytes()
		if err != nil {
			return DpResponseToSend{}, err
		}
		cr.AggregatingAttributesEnc[i] = data
	}
	if count {
		data, err := (*EncryptInt(encryptionKey, int64(1))).ToBytes()
		if err != nil {
			return DpResponseToSend{}, err
		}
		cr.AggregatingAttributesEnc["count"] = data
	}

	return cr, nil
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

// UnKey permits to go from a tag non-encrypted grouping attributes to grouping attributes
func UnKey(gk GroupingKey) ([]int64, error) {
	tab := make([]int64, 0)
	count := 0
	nbrString := make([]string, 1)
	for _, a := range gk {
		if a != ',' {
			nbrString[0] = string(a)
		} else {
			key, err := strconv.Atoi(strings.Join(nbrString, ""))
			if err != nil {
				return nil, err
			}
			tab = append(tab, int64(key))
			nbrString = make([]string, 1)
			count++
		}
	}
	return tab, nil
}

// Marshal
//______________________________________________________________________________________________________________________

// ToBytes converts a Filtered to a byte array
func (cv *FilteredResponse) ToBytes() ([]byte, int, int, error) {
	b := make([]byte, 0)
	pgaeb := make([]byte, 0)
	pgaebLength := 0

	aab, aabLength, err := (*cv).AggregatingAttributes.ToBytes()
	if err != nil {
		return nil, 0, 0, err
	}

	if (*cv).GroupByEnc != nil {
		pgaeb, pgaebLength, err = (*cv).GroupByEnc.ToBytes()
		if err != nil {
			return nil, 0, 0, err
		}
	}

	b = append(b, aab...)
	b = append(b, pgaeb...)

	return b, pgaebLength, aabLength, nil
}

// FromBytes converts a byte array to a FilteredResponse. Note that you need to create the (empty) object beforehand.
func (cv *FilteredResponse) FromBytes(data []byte, aabLength, pgaebLength int) error {
	(*cv).AggregatingAttributes = make(CipherVector, aabLength)
	(*cv).GroupByEnc = make(CipherVector, pgaebLength)

	lengthCipher := 2 * SuiTe.PointLen()
	aabByteLength := aabLength * lengthCipher
	pgaebByteLength := pgaebLength * lengthCipher

	aab := data[:aabByteLength]
	pgaeb := data[aabByteLength : aabByteLength+pgaebByteLength]

	err := (*cv).AggregatingAttributes.FromBytes(aab, aabLength)
	if err != nil {
		return err
	}
	err = (*cv).GroupByEnc.FromBytes(pgaeb, pgaebLength)
	if err != nil {
		return err
	}
	return nil
}

// ToBytes converts a FilteredResponseDet to a byte array
func (crd *FilteredResponseDet) ToBytes() ([]byte, int, int, int, error) {
	b, gacbLength, aabLength, err := (*crd).Fr.ToBytes()
	if err != nil {
		return nil, 0, 0, 0, err
	}

	dtbgb := []byte((*crd).DetTagGroupBy)
	dtbgbLength := len(dtbgb)

	b = append(b, dtbgb...)

	return b, gacbLength, aabLength, dtbgbLength, nil
}

// FromBytes converts a byte array to a FilteredResponseDet. Note that you need to create the (empty) object beforehand.
func (crd *FilteredResponseDet) FromBytes(data []byte, gacbLength, aabLength, dtbgbLength int) error {
	(*crd).Fr.AggregatingAttributes = make(CipherVector, aabLength)
	(*crd).Fr.GroupByEnc = make(CipherVector, gacbLength)

	lengthCipher := 2 * SuiTe.PointLen()
	aabByteLength := aabLength * lengthCipher //CAREFUL: hardcoded 64 (size of el-gamal element C,K)
	gacbByteLength := gacbLength * lengthCipher

	aab := data[:aabByteLength]
	gacb := data[aabByteLength : gacbByteLength+aabByteLength]
	dtbgb := data[gacbByteLength+aabByteLength : gacbByteLength+aabByteLength+dtbgbLength]

	(*crd).DetTagGroupBy = GroupingKey(string(dtbgb))
	err := (*crd).Fr.AggregatingAttributes.FromBytes(aab, aabLength)
	if err != nil {
		return err
	}
	err = (*crd).Fr.GroupByEnc.FromBytes(gacb, gacbLength)
	if err != nil {
		return err
	}
	return nil
}

// ToBytes converts a ProcessResponse to a byte array
func (cv *ProcessResponse) ToBytes() ([]byte, int, int, int, error) {
	b := make([]byte, 0)
	pgaeb := make([]byte, 0)
	pgaebLength := 0

	gacb, gacbLength, err := (*cv).GroupByEnc.ToBytes()
	if err != nil {
		return nil, 0, 0, 0, err
	}

	aab, aabLength, err := (*cv).AggregatingAttributes.ToBytes()
	if err != nil {
		return nil, 0, 0, 0, err
	}

	if (*cv).WhereEnc != nil {
		pgaeb, pgaebLength, err = (*cv).WhereEnc.ToBytes()
		if err != nil {
			return nil, 0, 0, 0, err
		}
	}

	b = append(b, gacb...)
	b = append(b, aab...)
	b = append(b, pgaeb...)

	return b, gacbLength, aabLength, pgaebLength, nil
}

// FromBytes converts a byte array to a ProcessResponse. Note that you need to create the (empty) object beforehand.
func (cv *ProcessResponse) FromBytes(data []byte, gacbLength, aabLength, pgaebLength int) error {
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

	err := (*cv).GroupByEnc.FromBytes(gacb, gacbLength)
	if err != nil {
		return err
	}
	err = (*cv).AggregatingAttributes.FromBytes(aab, aabLength)
	if err != nil {
		return err
	}
	err = (*cv).WhereEnc.FromBytes(pgaeb, pgaebLength)
	if err != nil {
		return err
	}
	return nil
}

// ToBytes converts a ProcessResponseDet to a byte array
func (crd *ProcessResponseDet) ToBytes() ([]byte, int, int, int, int, int, error) {
	b, gacbLength, aabLength, pgaebLength, err := (*crd).PR.ToBytes()
	if err != nil {
		return nil, 0, 0, 0, 0, 0, err
	}

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
	return b, gacbLength, aabLength, pgaebLength, dtbgbLength, dtbwLength, nil
}

// FromBytes converts a byte array to a ProcessResponseDet. Note that you need to create the (empty) object beforehand.
func (crd *ProcessResponseDet) FromBytes(data []byte, gacbLength, aabLength, pgaebLength, dtbgbLength, dtbwLength int) error {
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
	err := (*crd).PR.AggregatingAttributes.FromBytes(aab, aabLength)
	if err != nil {
		return err
	}
	err = (*crd).PR.WhereEnc.FromBytes(pgaeb, pgaebLength)
	if err != nil {
		return err
	}
	err = (*crd).PR.GroupByEnc.FromBytes(gacb, gacbLength)
	if err != nil {
		return err
	}
	return nil
}

// FromDpResponseToSend converts a DpResponseToSend to a DpResponse
func (dr *DpResponse) FromDpResponseToSend(dprts DpResponseToSend) error {
	var err error
	dr.GroupByClear = dprts.GroupByClear
	if len(dprts.GroupByEnc) != 0 {
		dr.GroupByEnc, err = MapBytesToMapCipherText(dprts.GroupByEnc)
		if err != nil {
			return err
		}
	}

	dr.WhereClear = dprts.WhereClear
	if len(dprts.WhereEnc) != 0 {
		dr.WhereEnc = make(map[string]CipherText)
		for i, v := range dprts.WhereEnc {
			ct := CipherText{}
			err = ct.FromBytes(v)
			if err != nil {
				return err
			}
			dr.WhereEnc[i] = ct
		}
	}
	dr.AggregatingAttributesClear = dprts.AggregatingAttributesClear
	if len(dprts.AggregatingAttributesEnc) != 0 {
		dr.AggregatingAttributesEnc = make(map[string]CipherText)
		for i, v := range dprts.AggregatingAttributesEnc {
			ct := CipherText{}
			err = ct.FromBytes(v)
			if err != nil {
				return err
			}
			dr.AggregatingAttributesEnc[i] = ct
		}
	}
	return nil
}

// MapBytesToMapCipherText transform objects in a map from bytes to ciphertexts
func MapBytesToMapCipherText(mapBytes map[string][]byte) (map[string]CipherText, error) {
	result := make(map[string]CipherText)
	if len(mapBytes) != 0 {
		for i, v := range mapBytes {
			ct := CipherText{}
			err := ct.FromBytes(v)
			if err != nil {
				return nil, err
			}
			result[i] = ct
		}
		return result, nil
	}
	return nil, nil
}
