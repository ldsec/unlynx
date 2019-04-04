package dataunlynx_test

import (
	"testing"

	"github.com/lca1/unlynx/data"
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
)

const filename = "unlynx_test_data.txt"
const numDPs = 2
const numEntries = 10
const numEntriesFiltered = 5
const numGroupsClear = 0
const numGroupsEnc = 2
const numWhereClear = 0
const numWhereEnc = 2
const numAggrClear = 0
const numAggrEnc = 2

var numType = [...]int64{2, 5}

var testData map[string][]libunlynx.DpClearResponse

func TestAllPossibleGroups(t *testing.T) {
	groups := make([][]int64, 0)
	group := make([]int64, 0)
	dataunlynx.AllPossibleGroups(numType[:], group, 0, &groups)

	numElem := 1
	for _, el := range numType {
		numElem = numElem * int(el)
	}
	assert.Equal(t, numElem, len(groups), "Some elements are missing")
}

func TestGenerateData(t *testing.T) {
	testData, _ = dataunlynx.GenerateData(numDPs, numEntries, numEntriesFiltered, numGroupsClear, numGroupsEnc,
		numWhereClear, numWhereEnc, numAggrClear, numAggrEnc, numType[:], true)
}

func TestWriteDataToFile(t *testing.T) {
	_ = dataunlynx.WriteDataToFile(filename, testData)
}

func TestReadDataFromFile(t *testing.T) {
	_, _ = dataunlynx.ReadDataFromFile(filename)
}

func TestCompareClearResponses(t *testing.T) {
	data, _ := dataunlynx.ReadDataFromFile(filename)
	assert.Equal(t, testData, data, "Data should be the same")
}

func TestComputeExpectedResult(t *testing.T) {
	data, _ := dataunlynx.ReadDataFromFile(filename)
	assert.Equal(t, dataunlynx.CompareClearResponses(dataunlynx.ComputeExpectedResult(testData, 1, false), dataunlynx.ComputeExpectedResult(data, 1, false)), true, "Result should be the same")
	assert.Equal(t, dataunlynx.CompareClearResponses(dataunlynx.ComputeExpectedResult(testData, 1, true), dataunlynx.ComputeExpectedResult(data, 1, true)), true, "Result should be the same")
}
