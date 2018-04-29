//Go file that regroup different tools functions used in the protocols
package protocolsunlynx

import (
    "github.com/lca1/unlynx/lib"
    "unsafe"
    "reflect"
    "errors"
)

// _____________________ COLLECTIVE_AGGREGATION PROTOCOL _____________________

func RetrieveSimpleDataFromMap(groupedData map[libunlynx.GroupingKey]libunlynx.FilteredResponse) ([]libunlynx.CipherText, error) {
    if len(groupedData) != 1 {
        return nil, errors.New("the map given in arguments is empty or have more than one key")
    }

    filteredResp, present := groupedData[EMPTYKEY]
    if present {
        result := make([]libunlynx.CipherText, len(filteredResp.AggregatingAttributes))
        for i, v := range filteredResp.AggregatingAttributes {
            result[i] = v
        }
        return result, nil
    } else {
        return nil, errors.New("the map element doesn't have key with value EMPTYKEY")
    }
}

// _____________________ DETERMINISTIC_TAGGING PROTOCOL _____________________

// CipherTextArray build from a ProcessResponse array
func ProcessResponseToCipherVector(p []libunlynx.ProcessResponse) libunlynx.CipherVector {
    cv := make(libunlynx.CipherVector, 0)

    for _, v := range p {
        cv = append(cv, v.WhereEnc...)
        cv = append(cv, v.GroupByEnc...)
    }

    return cv
}

// ProcessResponseDet build from DeterministCipherVector and the ProcessResponse
func DeterCipherVectorToProcessResponseDet(detCt libunlynx.DeterministCipherVector,
    targetOfSwitch []libunlynx.ProcessResponse) []libunlynx.ProcessResponseDet {
    result := make([]libunlynx.ProcessResponseDet, len(targetOfSwitch))

    pos := 0
    for i := range result {
        whereEncLen := len(targetOfSwitch[i].WhereEnc)
        deterministicWhereAttributes := make([]libunlynx.GroupingKey, whereEncLen)
        for j, c := range detCt[pos : pos+whereEncLen] {
            deterministicWhereAttributes[j] = libunlynx.GroupingKey(c.String())
        }
        pos += whereEncLen

        groupByLen := len(targetOfSwitch[i].GroupByEnc)
        deterministicGroupAttributes := make(libunlynx.DeterministCipherVector, groupByLen)
        copy(deterministicGroupAttributes, detCt[pos : pos+groupByLen])
        pos += groupByLen

        result[i] = libunlynx.ProcessResponseDet{PR: targetOfSwitch[i], DetTagGroupBy: deterministicGroupAttributes.Key(),
            DetTagWhere: deterministicWhereAttributes}
    }

    return result
}

// _____________________ KEY_SWITCHING PROTOCOL _____________________

// FilterResponse transformed into a CipherVector. Return also the lengths necessary to rebuild the function
func FilteredResponseToCipherVector(fr []libunlynx.FilteredResponse) (libunlynx.CipherVector, [][]int) {
    cv := make(libunlynx.CipherVector, 0)
    lengths := make([][]int, len(fr))

    for i, v := range fr {
        lengths[i] = make([]int, 2)
        cv = append(cv, v.GroupByEnc...)
        lengths[i][0] = len(v.GroupByEnc)
        cv = append(cv, v.AggregatingAttributes...)
        lengths[i][1] = len(v.AggregatingAttributes)
    }

    return cv, lengths
}

//CipherVector rebuild a FilteredResponse with the length of the FilteredResponse given in FilteredResponseToCipherVector
func CipherVectorToFilteredResponse(cv libunlynx.CipherVector, lengths [][]int) []libunlynx.FilteredResponse {
    filteredResponse := make([]libunlynx.FilteredResponse, len(lengths))

    pos := 0
    for i, length := range lengths {
        filteredResponse[i].GroupByEnc = make(libunlynx.CipherVector, length[0])
        copy(filteredResponse[i].GroupByEnc, cv[pos:pos+length[0]])
        pos += length[0]

        filteredResponse[i].AggregatingAttributes = make(libunlynx.CipherVector, length[1])
        copy(filteredResponse[i].AggregatingAttributes, cv[pos:pos+length[1]])
        pos += length[1]
    }

    return filteredResponse
}

// _____________________ SHUFFLING PROTOCOL _____________________

func ProcessResponseToMatrixCipherText(pr []libunlynx.ProcessResponse) ([]libunlynx.CipherVector, [][]int) {
    // We take care that array with one element have at least 2 with inserting a new 0 value
    if len(pr) == 1 {
        toAddPr := libunlynx.ProcessResponse{}
        toAddPr.GroupByEnc = pr[0].GroupByEnc
        toAddPr.WhereEnc = pr[0].WhereEnc
        toAddPr.AggregatingAttributes = make(libunlynx.CipherVector, len(pr[0].AggregatingAttributes))
        for i := range pr[0].AggregatingAttributes {
            toAddPr.AggregatingAttributes[i] = libunlynx.IntToCipherText(0)
        }
        pr = append(pr, toAddPr)
    }

    lengthPr := len(pr)
    cv := make([]libunlynx.CipherVector, lengthPr)
    lengths := make([][]int, lengthPr)
    for i, v := range pr {
        cv[i] = append(cv[i], v.GroupByEnc...)
        cv[i] = append(cv[i], v.WhereEnc...)
        cv[i] = append(cv[i], v.AggregatingAttributes...)
        lengths[i] = make([]int, 2)
        lengths[i][0] = len(v.GroupByEnc)
        lengths[i][1] = len(v.WhereEnc)
    }

    return cv, lengths
}

func MatrixCipherTextToProcessResponse(cv []libunlynx.CipherVector, lengths [][]int) []libunlynx.ProcessResponse {
    pr := make([]libunlynx.ProcessResponse, len(lengths))
    for i, length := range lengths {
        groupByEncPos := length[0]
        whereEncPos := groupByEncPos + length[1]
        pr[i].GroupByEnc = cv[i][:groupByEncPos]
        pr[i].WhereEnc = cv[i][groupByEncPos:whereEncPos]
        pr[i].AggregatingAttributes = cv[i][whereEncPos:]
    }
    return pr
}

func AdaptCipherTextArray(cipherTexts []libunlynx.CipherText) []libunlynx.CipherVector {
    result := make([]libunlynx.CipherVector, len(cipherTexts))
    for i, v := range cipherTexts {
        result[i] = make([]libunlynx.CipherText, 1)
        result[i][0] = v
    }
    return result
}

// cast using reflect []int <-> []byte
// from http://stackoverflow.com/questions/17539001/converting-int32-to-byte-array-in-go

// IntByteSize is the byte size of an int in memory
const IntByteSize = int(unsafe.Sizeof(int(0)))

// UnsafeCastIntsToBytes casts a slice of ints to a slice of bytes
func UnsafeCastIntsToBytes(ints []int) []byte {
    length := len(ints) * IntByteSize
    hdr := reflect.SliceHeader{Data: uintptr(unsafe.Pointer(&ints[0])), Len: length, Cap: length}
    return *(*[]byte)(unsafe.Pointer(&hdr))
}

// UnsafeCastBytesToInts casts a slice of bytes to a slice of ints
func UnsafeCastBytesToInts(bytes []byte) []int {
    length := len(bytes) / IntByteSize
    hdr := reflect.SliceHeader{Data: uintptr(unsafe.Pointer(&bytes[0])), Len: length, Cap: length}
    return *(*[]int)(unsafe.Pointer(&hdr))
}
