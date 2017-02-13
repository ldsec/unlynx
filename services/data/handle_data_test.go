package data_test

import (
	"testing"

	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/JoaoAndreSa/MedCo/services/data"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/onet.v1/log"
)

const filename = "medco_test_data.txt"
const num_clients = 1
const num_entries = 10
const num_groups = 2

var num_type = [...]int64{2, 5}

const num_aggr = 100

var test_data map[string][]lib.ClientClearResponse

func TestAllPossibleGroups(t *testing.T) {
	data.Groups = make([][]int64, 0)

	group := make([]int64, 0)
	data.AllPossibleGroups(num_type[:], group, 0)

	num_elem := 1
	for _, el := range num_type {
		num_elem = num_elem * int(el)
	}
	log.LLvl1(data.Groups)
	assert.Equal(t, num_elem, len(data.Groups), "Some elements are missing")
}

func TestGenerateData(t *testing.T) {
	test_data = data.GenerateData(num_clients, num_entries, num_groups, num_aggr, num_type[:], false)
}

func TestWriteDataToFile(t *testing.T) {
	data.WriteDataToFile(filename, test_data)
}

func TestReadDataFromFile(t *testing.T) {
	data.ReadDataFromFile(filename)
}

func TestComputeExpectedResult(t *testing.T) {
	assert.Equal(t, test_data, data.ReadDataFromFile(filename), "Data should be the same")
}

func TestCompareClearResponses(t *testing.T) {
	assert.Equal(t, data.CompareClearResponses(data.ComputeExpectedResult(test_data), data.ComputeExpectedResult(data.ReadDataFromFile(filename))), true, "Result should be the same")
}
