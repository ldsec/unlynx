package dataunlynx

import (
	"bufio"
	"fmt"
	"math"
	"math/rand"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/ldsec/unlynx/lib"
	"github.com/ldsec/unlynx/lib/store"
	"github.com/ldsec/unlynx/lib/tools"
)

// FillInt64Slice fills a slice with the same value v
func FillInt64Slice(s []int64, v int64) {
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
func AllPossibleGroups(numType []int64, group []int64, pos int, groups *[][]int64) {
	if pos == len(numType) {
		tmp := make([]int64, 0)
		for _, el := range group {
			tmp = append(tmp, el)
		}
		*groups = append(*groups, tmp)
	} else {
		for i := 0; i < int(numType[pos]); i++ {
			group = append(group, int64(i))

			pos++
			AllPossibleGroups(numType, group, pos, groups)
			pos--

			group = append(group[:len(group)-1], group[len(group):]...)
		}
	}
}

// GenerateData generates test data for UnLynx (survey entries) and stores it in a txt file (e.g. unlynx_test_data.txt)
//
//  	filename:    name of the file (.txt) where we will store the test data
//
//	    numDPs: 		    number of clients/hosts (or in other words data holders)
//  	numEntries: 		number of survey entries (ClientClearResponse) per host
//	    numEntriesFiltered: number of survey entries to keep (after the where filtering)
//  	numGroupsClear: 	number of grouping attributes in clear
//      numGroupsEnc:   	number of grouping attributes encrypted
//  	numWhereClear: 		number of where attributes in clear
//      numWhereEnc:   		number of where attributes encrypted
//  	numAggrClear:   	number of aggregating attributes in clear
//  	numAggrEnc:    		number of aggregating attributes encrypted
//  	numType:    		number of different groups inside a group attribute
//	    randomGroups: 		true -> groups are generated randomly, false -> we cover all possible groups
//TODO where + whereClear
func GenerateData(numDPs, numEntries, numEntriesFiltered, numGroupsClear, numGroupsEnc,
	numWhereClear, numWhereEnc, numAggrClear, numAggrEnc int64, numType []int64, randomGroups bool) (map[string][]libunlynx.DpClearResponse, error) {

	if int64(len(numType)) != (numGroupsClear + numGroupsEnc) {
		return nil, fmt.Errorf("specify the correct number of group types for each grouping attribute")
	}

	testData := make(map[string][]libunlynx.DpClearResponse)

	if !randomGroups {
		numElem := 1
		for _, el := range numType {
			numElem = numElem * int(el)
		}

		if int64(numElem) == numEntries {
			groups := make([][]int64, 0)
			group := make([]int64, 0)
			AllPossibleGroups(numType[:], group, 0, &groups)
		} else {
			return nil, fmt.Errorf("the number of groups is different from the number of entries")
		}
	}

	groups := make([][]int64, 0)
	for i := int64(0); i < numDPs; i++ {
		dpData := make([]libunlynx.DpClearResponse, numEntries)

		for j := int64(0); j < numEntries; j++ {
			aggr := make([]int64, numAggrEnc+numAggrClear)

			// Toggle random data or not (2 -> just 0's or 1's)
			randomFillInt64Slice(aggr, 2)

			grp := make([]int64, numGroupsClear+numGroupsEnc)

			where := make([]int64, numWhereClear+numWhereEnc)

			//number of entries to keep (all where attributes are set to 1)
			if j < numEntriesFiltered {
				FillInt64Slice(where, 1)
			} else {
				FillInt64Slice(where, 0)
			}

			if randomGroups {
				for k := range grp {
					grp[k] = int64(random(0, int(numType[k])))
				}
			} else {
				grp = groups[j]
			}

			dpData[j] = libunlynx.DpClearResponse{
				GroupByClear:               libunlynxtools.ConvertDataToMap(grp[:numGroupsClear], "g", 0),
				GroupByEnc:                 libunlynxtools.ConvertDataToMap(grp[numGroupsClear:numGroupsClear+numGroupsEnc], "g", int(numGroupsClear)),
				WhereClear:                 libunlynxtools.ConvertDataToMap(where[:numWhereClear], "w", 0),
				WhereEnc:                   libunlynxtools.ConvertDataToMap(where[numWhereClear:numWhereClear+numWhereEnc], "w", int(numWhereClear)),
				AggregatingAttributesClear: libunlynxtools.ConvertDataToMap(aggr[:numAggrClear], "s", 0),
				AggregatingAttributesEnc:   libunlynxtools.ConvertDataToMap(aggr[numAggrClear:numAggrClear+numAggrEnc], "s", int(numAggrClear)),
			}

		}
		testData[fmt.Sprintf("%v", i)] = dpData
	}
	return testData, nil
}

// flushInt64Data writes a slice of int64 data to file (writer is the file handler)
func flushInt64Data(writer *bufio.Writer, slice []int64) error {
	for _, g := range slice {
		if _, err := fmt.Fprint(writer, fmt.Sprintf("%v ", g)); err != nil {
			return err
		}
		if err := writer.Flush(); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprint(writer, "\n"); err != nil {
		return err
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	return nil
}

// CreateInt64Slice creates a slice of int64 between min and max
func CreateInt64Slice(size int64, min int64, max int64) []int64 {
	slice := make([]int64, size)
	for i := 0; i < int(size); i++ {
		slice[i] = int64(random(int(min), int(max)))
	}
	return slice
}

// WriteDataToFile writes the testData to 'filename'.txt
func WriteDataToFile(filename string, testData map[string][]libunlynx.DpClearResponse) error {
	fileHandle, err := os.Create(filename)
	if err != nil {
		return err
	}

	writer := bufio.NewWriter(fileHandle)
	if err := writer.Flush(); err != nil {
		return err
	}
	defer fileHandle.Close()

	for k, v := range testData {
		if _, err := fmt.Fprintln(writer, "#"+k); err != nil {
			return err
		}
		if err := writer.Flush(); err != nil {
			return err
		}

		for _, entry := range v {
			if err := flushInt64Data(writer, libunlynxtools.ConvertMapToData(entry.GroupByClear, "g", 0)); err != nil {
				return err
			}
			if err := flushInt64Data(writer, libunlynxtools.ConvertMapToData(entry.GroupByEnc, "g", len(entry.GroupByClear))); err != nil {
				return err
			}
			if err := flushInt64Data(writer, libunlynxtools.ConvertMapToData(entry.WhereClear, "w", 0)); err != nil {
				return err
			}
			if err := flushInt64Data(writer, libunlynxtools.ConvertMapToData(entry.WhereEnc, "w", len(entry.WhereClear))); err != nil {
				return err
			}
			if err := flushInt64Data(writer, libunlynxtools.ConvertMapToData(entry.AggregatingAttributesClear, "s", 0)); err != nil {
				return err
			}
			if err := flushInt64Data(writer, libunlynxtools.ConvertMapToData(entry.AggregatingAttributesEnc, "s", len(entry.AggregatingAttributesClear))); err != nil {
				return err
			}
		}
	}
	return nil
}

// ReadDataFromFile reads the testData from 'filename'.txt
func ReadDataFromFile(filename string) (map[string][]libunlynx.DpClearResponse, error) {
	testData := make(map[string][]libunlynx.DpClearResponse)

	fileHandle, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer fileHandle.Close()

	var id string
	dataIn := false
	var container []libunlynx.DpClearResponse

	scanner := bufio.NewScanner(fileHandle)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > 0 && strings.Compare(string(line[0]), "#") == 0 {
			if dataIn != false {
				testData[id] = container
				container = make([]libunlynx.DpClearResponse, 0)
			} else {
				dataIn = true
			}
			id = line[1:]
		} else {
			// Grouping Attributes Clear
			grpClear := libunlynxtools.StringToInt64Array(line[:int(math.Max(float64(0), float64(len(line)-1)))])

			// Grouping Attributes Encrypted
			scanner.Scan()
			grpEnc := libunlynxtools.StringToInt64Array(scanner.Text()[:int(math.Max(float64(0), float64(len(scanner.Text())-1)))])

			// Where Attributes Clear
			scanner.Scan()
			whereClear := libunlynxtools.StringToInt64Array(scanner.Text()[:int(math.Max(float64(0), float64(len(scanner.Text())-1)))])

			// Where Attributes Encrypted
			scanner.Scan()
			whereEnc := libunlynxtools.StringToInt64Array(scanner.Text()[:int(math.Max(float64(0), float64(len(scanner.Text())-1)))])

			// Aggregating Attributes Clear
			scanner.Scan()
			aggrClear := libunlynxtools.StringToInt64Array(scanner.Text()[:int(math.Max(float64(0), float64(len(scanner.Text())-1)))])

			// Aggregating Attributes Encrypted
			scanner.Scan()
			aggrEnc := libunlynxtools.StringToInt64Array(scanner.Text()[:int(math.Max(float64(0), float64(len(scanner.Text())-1)))])

			container = append(container, libunlynx.DpClearResponse{
				GroupByClear:               libunlynxtools.ConvertDataToMap(grpClear, "g", 0),
				GroupByEnc:                 libunlynxtools.ConvertDataToMap(grpEnc, "g", len(grpClear)),
				WhereClear:                 libunlynxtools.ConvertDataToMap(whereClear, "w", 0),
				WhereEnc:                   libunlynxtools.ConvertDataToMap(whereEnc, "w", len(whereClear)),
				AggregatingAttributesClear: libunlynxtools.ConvertDataToMap(aggrClear, "s", 0),
				AggregatingAttributesEnc:   libunlynxtools.ConvertDataToMap(aggrEnc, "s", len(aggrClear)),
			})
		}
	}
	testData[id] = container

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return testData, nil
}

// joinMaps concatenates two similar maps of type map[string]int64
func joinMaps(a, b map[string]int64) map[string]int64 {
	concat := make(map[string]int64)

	for k, v := range a {
		concat[k] = v
	}

	for k, v := range b {
		concat[k] = v
	}

	return concat
}

// ClearExpectedResult clears the map so that there are no where attributes
func ClearExpectedResult(expectedResult []libunlynx.DpClearResponse) []libunlynx.DpClearResponse {
	clearExpectedResult := make([]libunlynx.DpClearResponse, len(expectedResult))

	for i, elem := range expectedResult {
		elem.WhereClear = map[string]int64{}
		elem.WhereEnc = map[string]int64{}
		elem.GroupByClear = joinMaps(elem.GroupByClear, elem.GroupByEnc)
		elem.GroupByEnc = map[string]int64{}
		elem.AggregatingAttributesClear = joinMaps(elem.AggregatingAttributesClear, elem.AggregatingAttributesEnc)
		elem.AggregatingAttributesEnc = map[string]int64{}

		clearExpectedResult[i] = elem
	}

	return clearExpectedResult
}

// ComputeExpectedResult computes the expected results from the testData (we can then compare with the result obtained by service UnLynx)
func ComputeExpectedResult(testData map[string][]libunlynx.DpClearResponse, dataRepetitions int, clear bool) []libunlynx.DpClearResponse {
	allData := make([]libunlynx.DpClearResponse, 0)

	for _, v := range testData {
		for _, elem := range v {

			//if we repeated data
			if dataRepetitions > 1 {
				for k := range elem.AggregatingAttributesClear {
					elem.AggregatingAttributesClear[k] = elem.AggregatingAttributesClear[k] * int64(dataRepetitions)
				}
				for k := range elem.AggregatingAttributesEnc {
					elem.AggregatingAttributesEnc[k] = elem.AggregatingAttributesEnc[k] * int64(dataRepetitions)
				}
			}

			allData = append(allData, elem)
		}
	}
	expectedResult := libunlynxstore.AddInClear(allData)

	// Toggle the clearing function (necessary for the service simulation)
	if clear {
		expectedResult = ClearExpectedResult(expectedResult)
	}

	return expectedResult
}

// CompareClearResponses compares two DP ClearResponse arrays and returns true if they are the same or false otherwise
func CompareClearResponses(x []libunlynx.DpClearResponse, y []libunlynx.DpClearResponse) bool {
	var test bool
	for _, i := range x {
		test = false
		for _, j := range y {
			if (reflect.DeepEqual(i.GroupByClear, j.GroupByClear) || (len(i.GroupByClear) == 0 && len(j.GroupByClear) == 0)) &&
				(reflect.DeepEqual(i.GroupByEnc, j.GroupByEnc) || (len(i.GroupByEnc) == 0 && len(j.GroupByEnc) == 0)) &&
				(reflect.DeepEqual(i.WhereClear, j.WhereClear) || (len(i.WhereClear) == 0 && len(j.WhereClear) == 0)) &&
				(reflect.DeepEqual(i.WhereEnc, j.WhereEnc) || (len(i.WhereEnc) == 0 && len(j.WhereEnc) == 0)) &&
				(reflect.DeepEqual(i.AggregatingAttributesClear, j.AggregatingAttributesClear) || (len(i.AggregatingAttributesClear) == 0 && len(j.AggregatingAttributesClear) == 0)) &&
				(reflect.DeepEqual(i.AggregatingAttributesEnc, j.AggregatingAttributesEnc) || (len(i.AggregatingAttributesEnc) == 0 && len(j.AggregatingAttributesEnc) == 0)) {

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
