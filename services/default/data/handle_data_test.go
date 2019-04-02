package dataunlynx_test

import (
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/services/default/data"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/onet/v3/log"
	"testing"
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
	testData = dataunlynx.GenerateData(numDPs, numEntries, numEntriesFiltered, numGroupsClear, numGroupsEnc,
		numWhereClear, numWhereEnc, numAggrClear, numAggrEnc, numType[:], true)
}

func TestWriteDataToFile(t *testing.T) {
	dataunlynx.WriteDataToFile(filename, testData)
}

func TestReadDataFromFile(t *testing.T) {
	dataunlynx.ReadDataFromFile(filename)
}

func TestCompareClearResponses(t *testing.T) {
	dataunlynx.ReadDataFromFile(filename)
	assert.Equal(t, testData, dataunlynx.ReadDataFromFile(filename), "Data should be the same")
}

func TestComputeExpectedResult(t *testing.T) {
	log.Lvl1(dataunlynx.ComputeExpectedResult(dataunlynx.ReadDataFromFile(filename), 1, false))
	assert.Equal(t, dataunlynx.CompareClearResponses(dataunlynx.ComputeExpectedResult(testData, 1, false), dataunlynx.ComputeExpectedResult(dataunlynx.ReadDataFromFile(filename), 1, false)), true, "Result should be the same")
	assert.Equal(t, dataunlynx.CompareClearResponses(dataunlynx.ComputeExpectedResult(testData, 1, true), dataunlynx.ComputeExpectedResult(dataunlynx.ReadDataFromFile(filename), 1, true)), true, "Result should be the same")
}
