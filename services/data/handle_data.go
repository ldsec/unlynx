package data

import (

)

// Groups identifies all different groups to be added to the test data file
/*var Groups [][]int64

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
//	numDPs: 	number of clients/hosts (or in other words data holders)
//  	numEntries: 	number of survey entries (ClientClearResponse) per host
//  	numGroupsClear: number of grouping attributes in clear
//      numGroupsEnc:   number of grouping attributes encrypted
//  	numType:    	number of different groups inside a group attribute
//  	numAggr:    	number of aggregating attributes
//TODO where + whereClear
func GenerateData(numDPs, numEntries, numEntriesToKeep, numGroupsClear, numGroupsEnc, numAggr int64, numType []int64, randomGroups bool) map[string][]lib.DpClearResponse {
	if int64(len(numType)) != (numGroupsClear + numGroupsEnc) {
		log.Fatal("Please ensure that you specify the number of group types for each grouping attribute")
		return nil
	}

	testData := make(map[string][]lib.DpClearResponse)

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

	for i := int64(0); i < numDPs; i++ {
		dpData := make([]lib.DpClearResponse, numEntries)

		for j := int64(0); j < numEntries; j++ {
			aggr := make([]int64, numAggr)
			// Toggle random data or not (just 0's or 1's)

			//FillInt64Slice(aggr,int64(1))
			randomFillInt64Slice(aggr, 2)

			grp := make([]int64, numGroupsClear+numGroupsEnc)

			if randomGroups {
				for k := range grp {
					grp[k] = int64(random(0, int(numType[k])))
				}
			} else {
				grp = Groups[j]
			}

			dpData[j] = lib.DpClearResponse{GroupByClear: grp[:numGroupsClear], GroupByEnc: grp[numGroupsClear : numGroupsClear+numGroupsEnc], AggregatingAttributes: aggr}

		}
		testData[fmt.Sprintf("%v", i)] = dpData
	}
	return testData
}

// flushInt64Data writes a slice of int64 data to file (writer is the file handler)
func flushInt64Data(writer *bufio.Writer, slice []int64) {
	for _, g := range slice {
		fmt.Fprint(writer, fmt.Sprintf("%v ", g))
		writer.Flush()
	}

	fmt.Fprint(writer, "\n")
	writer.Flush()
}

// WriteDataToFile writes the test_data to 'filename'.txt
func WriteDataToFile(filename string, testData map[string][]lib.DpClearResponse) {
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
			flushInt64Data(writer, entry.GroupByClear)
			flushInt64Data(writer, entry.GroupByEnc)
			flushInt64Data(writer, entry.AggregatingAttributes)
		}
	}
}

// ReadDataFromFile reads the test_data from 'filename'.txt
func ReadDataFromFile(filename string) map[string][]lib.DpClearResponse {
	testData := make(map[string][]lib.DpClearResponse)

	fileHandle, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
		return nil
	}
	defer fileHandle.Close()

	var id string
	dataIn := false
	var container []lib.DpClearResponse

	scanner := bufio.NewScanner(fileHandle)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > 0 && strings.Compare(string(line[0]), "#") == 0 {
			if dataIn != false {
				testData[id] = container
				container = make([]lib.DpClearResponse, 0)
			} else {
				dataIn = true
			}
			id = line[1:]
		} else {
			// Grouping Attributes Clear
			grpClear := lib.StringToInt64Array(line[:int(math.Max(float64(0), float64(len(line)-1)))])

			// Grouping Attributes Encrypted
			scanner.Scan()
			grpEnc := lib.StringToInt64Array(scanner.Text()[:int(math.Max(float64(0), float64(len(scanner.Text())-1)))])

			// Aggregating Attributes
			scanner.Scan()
			aggr := lib.StringToInt64Array(scanner.Text()[:int(math.Max(float64(0), float64(len(scanner.Text())-1)))])

			container = append(container, lib.DpClearResponse{GroupByClear: grpClear, GroupByEnc: grpEnc, AggregatingAttributes: aggr})
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
func ComputeExpectedResult(testData map[string][]lib.DpClearResponse, dataRepetitions int) []lib.DpClearResponse {
	allData := make([]lib.DpClearResponse, 0)

	for _, v := range testData {
		for _, elem := range v {

			if dataRepetitions > 1 {
				for i := range elem.AggregatingAttributes {
					elem.AggregatingAttributes[i] = elem.AggregatingAttributes[i] * int64(dataRepetitions)
				}
			}

			allData = append(allData, elem)
		}
	}
	expectedResult := lib.AddInClear(allData)
	log.LLvl1(expectedResult)
	return expectedResult
}

// CompareClearResponses compares two DP ClearResponse arrays and returns true if they are the same or false otherwise
func CompareClearResponses(x []lib.DpClearResponse, y []lib.DpClearResponse) bool {
	var test bool
	for _, i := range x {
		test = false
		for _, j := range y {
			if (reflect.DeepEqual(i.GroupByClear, j.GroupByClear) || (len(i.GroupByClear) == 0 && len(j.GroupByClear) == 0)) &&
				(reflect.DeepEqual(i.GroupByEnc, j.GroupByEnc) || (len(i.GroupByEnc) == 0 && len(j.GroupByEnc) == 0)) &&
				(reflect.DeepEqual(i.AggregatingAttributes, j.AggregatingAttributes) || (len(i.AggregatingAttributes) == 0 && len(j.AggregatingAttributes) == 0)) {
				test = true
				break
			}
		}

		if !test {
			break
		}
	}

	return test
}*/
