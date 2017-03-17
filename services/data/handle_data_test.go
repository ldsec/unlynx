package data_test

import (
	"testing"

	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/JoaoAndreSa/MedCo/services/data"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/onet.v1/log"
)

const filename = "medco_test_data.txt"
const numDPs = 2
const numEntries = 20
const numGroupsClear = 2
const numGroupsEnc = 1

var num_type = [...]int64{2, 5, 2}

const num_aggr = 5

var test_data map[string][]lib.DpClearResponse

func TestAllPossibleGroups(t *testing.T) {
	data.Groups = make([][]int64, 0)

	group := make([]int64, 0)
	data.AllPossibleGroups(num_type[:], group, 0)

	num_elem := 1
	for _, el := range num_type {
		num_elem = num_elem * int(el)
	}
	assert.Equal(t, num_elem, len(data.Groups), "Some elements are missing")
}

func TestConvertDataToMap(t *testing.T) {
	test := []int64{0,1,2,3,4}

	result := make(map[string]int64)
	result["g0"] = 0
	result["g1"] = 1
	result["g2"] = 2
	result["g3"] = 3
	result["g4"] = 4

	assert.Equal(t, result, data.ConvertDataToMap(test,"g"), "Wrong map conversion")
}

func TestGenerateData(t *testing.T) {
	test_data = data.GenerateData(numDPs, numEntries, numGroupsClear, numGroupsEnc, num_aggr, num_type[:], false)
}

func TestWriteDataToFile(t *testing.T) {
	data.WriteDataToFile(filename, test_data)
}

func TestReadDataFromFile(t *testing.T) {
	data.ReadDataFromFile(filename)
}

func TestComputeExpectedResult(t *testing.T) {
	log.LLvl1(data.ReadDataFromFile(filename))
	assert.Equal(t, test_data, data.ReadDataFromFile(filename), "Data should be the same")
}

func TestCompareClearResponses(t *testing.T) {
	log.LLvl1(data.ComputeExpectedResult(data.ReadDataFromFile(filename), 1))
	assert.Equal(t, data.CompareClearResponses(data.ComputeExpectedResult(test_data, 1), data.ComputeExpectedResult(data.ReadDataFromFile(filename), 1)), true, "Result should be the same")
}
