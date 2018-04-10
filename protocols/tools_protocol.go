//Go file that regroup different tools functions used in the protocols
package protocolsunlynx

import "github.com/lca1/unlynx/lib"

// CypherTextArray build from a ProcessResponse array
func PRToCipherTextArray(p []libunlynx.ProcessResponse) ([]libunlynx.CipherText) {
    cipherTexts := make([]libunlynx.CipherText, 0)

    for _, v := range p {
        cipherTexts = append(cipherTexts, v.WhereEnc...)
        cipherTexts = append(cipherTexts, v.GroupByEnc...)
    }

    return cipherTexts
}

// ProcessResponseDet build from DeterministicCipherVector and the ProcessResponse
func DCVToProcessResponseDet(detCt libunlynx.DeterministCipherVector,
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
