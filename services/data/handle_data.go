package data

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"strings"
	"time"

	"gopkg.in/dedis/onet.v1/log"
	"github.com/JoaoAndreSa/MedCo/lib"
)

// Groups identifies all different groups to be added to the test data file
var Groups [][]int64

// fillInt64Slice fills a slice with the same value v
func fillInt64Slice(s []int64, v int64) {
	for i := 0; i < len(s); i++ {
		s[i] = v
	}
}

// random generates a random number between min and max
func random(min, max int) int {
	rand.Seed(time.Now().UTC().UnixNano())
	return rand.Intn(max-min) + min
}

// RandomFillInt64Slice fills a slice with random values between 0 and max
func randomFillInt64Slice(s []int64, max int64) {
	for i := 0; i < len(s); i++ {
		s[i] = int64(random(0, int(max)))
	}
}

// AllPossibleGroups generates all possible groups given the different groups for the grouping attributes
// e.g. numType:1,2 -> Groups: [0,0], [0,1]
func AllPossibleGroups(numType []int64, group []int64, pos int) {
	if pos == len(numType) {
		tmp := make([]int64, 0)
		for _, el := range group {
			tmp = append(tmp, el)
		}
		Groups = append(Groups, tmp)
	} else {
		for i := 0; i < int(numType[pos]); i++ {
			group = append(group, int64(i))

			pos++
			AllPossibleGroups(numType, group, pos)
			pos--

			group = append(group[:len(group)-1], group[len(group):]...)
		}
	}
}

// GenerateData generates test data for MedCo (survey entries) and stores it in a txt file (e.g. medco_test_data.txt)
//
//  	filename:    name of the file (.txt) where we will store the test data
//
//	num_clients: number of clients/hosts (or in other words data holders)
//  	num_entries: number of survey entries (ClientClearResponse) per host
//  	num_groups:  number of grouping attributes
//  	num_type:    number of different groups inside a group attribute
//  	num_aggr:    number of aggregating attributes
func GenerateData(numClients, numEntries, numGroups, numAggr int64, numType []int64, randomGroups bool) map[string][]lib.ClientClearResponse {
	testData := make(map[string][]lib.ClientClearResponse)

	if !randomGroups {
		numElem := 1
		for _, el := range numType {
			numElem = numElem * int(el)
		}

		if int64(numElem) == numEntries {
			Groups = make([][]int64, 0)
			group := make([]int64, 0)
			AllPossibleGroups(numType[:], group, 0)
		} else {
			log.Fatal("Please ensure that the number of groups is the same as the number of entries")
			return nil
		}
	}

	for i := int64(0); i < numClients; i++ {
		clientData := make([]lib.ClientClearResponse, numEntries)

		for j := int64(0); j < numEntries; j++ {
			aggr := make([]int64, numAggr)
			// Toggle random data or not

			//FillInt64Slice(aggr,int64(1))
			randomFillInt64Slice(aggr, 2)

			grp := make([]int64, numGroups)

			if randomGroups {
				for k := range grp {
					grp[k] = int64(random(0, int(numType[k])))
				}
			} else {
				grp = Groups[j]
			}

			clientData[j] = lib.ClientClearResponse{GroupingAttributesClear: grp, AggregatingAttributes: aggr}

		}
		testData[fmt.Sprintf("%v", i)] = clientData
	}

	return testData
}

// WriteDataToFile writes the test_data to 'filename'.txt
func WriteDataToFile(filename string, testData map[string][]lib.ClientClearResponse) {
	fileHandle, err := os.Create(filename)

	if err != nil {
		log.Fatal(err)
	}

	writer := bufio.NewWriter(fileHandle)
	defer fileHandle.Close()

	for k, v := range testData {
		fmt.Fprintln(writer, "#"+k)
		writer.Flush()

		for _, entry := range v {
			for _, g := range entry.GroupingAttributesClear {
				fmt.Fprint(writer, fmt.Sprintf("%v ", g))
				writer.Flush()
			}

			fmt.Fprint(writer, "\n")
			writer.Flush()

			for _, a := range entry.AggregatingAttributes {
				fmt.Fprint(writer, fmt.Sprintf("%v ", a))
				writer.Flush()
			}

			fmt.Fprint(writer, "\n")
			writer.Flush()
		}
	}
}

// ReadDataFromFile reads the test_data from 'filename'.txt
func ReadDataFromFile(filename string) map[string][]lib.ClientClearResponse {
	testData := make(map[string][]lib.ClientClearResponse)

	fileHandle, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
		return nil
	}
	defer fileHandle.Close()

	var id string
	dataIn := false
	var container []lib.ClientClearResponse

	scanner := bufio.NewScanner(fileHandle)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.Compare(string(line[0]), "#") == 0 {
			if dataIn != false {
				testData[id] = container
				container = make([]lib.ClientClearResponse, 0)
			} else {
				dataIn = true
			}
			id = line[1:]
		} else {
			line = line[:len(line)-1]
			grp := lib.StringToInt64Array(line)

			scanner.Scan()
			aggr := lib.StringToInt64Array(scanner.Text()[:len(scanner.Text())-1])

			container = append(container, lib.ClientClearResponse{GroupingAttributesClear: grp, AggregatingAttributes: aggr})
		}
	}
	testData[id] = container

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
		return nil
	}

	return testData
}

// ComputeExpectedResult computes the expected results from the test_data (we can then compare with the result obtained by service MedCo)
func ComputeExpectedResult(testData map[string][]lib.ClientClearResponse) []lib.ClientClearResponse {
	allData := make([]lib.ClientClearResponse, 0)

	for _, v := range testData {
		for _, elem := range v {
			allData = append(allData, elem)
		}
	}

	expectedResult := lib.AddInClear(allData)
	return expectedResult
}

// CompareClearResponses compares two ClientClearResponse arrays and returns true if they are the same or false otherwise
func CompareClearResponses(x []lib.ClientClearResponse, y []lib.ClientClearResponse) bool {
	var test bool
	for _, i := range x {
		test = false
		for _, j := range y {
			if 	(reflect.DeepEqual(i.GroupingAttributesClear, j.GroupingAttributesClear) || (len(i.GroupingAttributesClear)==0 && len(j.GroupingAttributesClear)==0)) &&
				(reflect.DeepEqual(i.GroupingAttributesEnc, j.GroupingAttributesEnc) 	 || (len(i.GroupingAttributesEnc)==0 && len(j.GroupingAttributesEnc)==0)) &&
				(reflect.DeepEqual(i.AggregatingAttributes, j.AggregatingAttributes) 	 || (len(i.AggregatingAttributes)==0 && len(j.AggregatingAttributes)==0)) {
				test = true
				break
			}
		}

		if !test {
			break
		}
	}

	return test
}
