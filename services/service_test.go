package services_test

import (
	"reflect"
	"testing"

	"os"

	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1"
	"github.com/JoaoAndreSa/MedCo/services"
	"github.com/JoaoAndreSa/MedCo/lib"
)

// numberGrpAttr is the number of group attributes.
const numberGrpAttr = 2

// numberAttr is the number of attributes.
const numberAttr = 10

const proofsService = true

func TestMain(m *testing.M) {
	log.MainTest(m)
}

// TEST BATCH 1 -> encrypted or/and non-encrypted grouping attributes
//______________________________________________________________________________________________________________________

// Only encrypted attributes
func TestServiceOnlyEncGrpAttr(t *testing.T) {
	log.LLvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest()
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(5, true)
	defer local.CloseAll()

	// Send a request to the service
	client := services.NewMedcoClient(el.List[0])

	surveyDesc := lib.SurveyDescription{GroupingAttributesClearCount: 0, GroupingAttributesEncCount: numberGrpAttr, AggregatingAttributesCount: numberAttr}

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	for _, server := range el.List {
		nbrDPs[server.String()] = 2 // 2 DPs for each server
	}

	surveyID, _, err := client.SendSurveyCreationQuery(el, lib.SurveyID("testSurvey"), lib.SurveyID(""), surveyDesc, proofsService, false, nil, nil, nil, nbrDPs, 0)

	if err != nil {
		t.Fatal("Service did not start.")
	}

	//save values in a map to verify them at the end
	expectedResults := make(map[[numberGrpAttr]int64][]int64)
	log.Lvl1("Sending response data... ")
	dataHolder := make([]*services.API, 10)
	for i := 0; i < len(dataHolder); i++ {
		dataHolder[i] = services.NewMedcoClient(el.List[i%5])
		grp := [numberGrpAttr]int64{}
		aggr := make([]int64, numberAttr)

		//just random data
		//client1 -> grp:[1 0], aggr:[3 0 0 0 0 0 0 0 0 0]
		//client2 -> grp:[2 0], aggr:[0 3 0 0 0 0 0 0 0 0]
		//client3 -> grp:[3 0], aggr:[0 0 3 0 0 0 0 0 0 0]
		//...
		grp[0] = int64(i % 4)
		aggr[i%numberAttr] = 3

		//convert tab in slice (was a tab only for the test)
		sliceGrp := make([]int64, numberGrpAttr)
		for i, v := range grp {
			if i == 0 {
				sliceGrp = []int64{v}
			} else {
				sliceGrp = append(sliceGrp, v)
			}
		}

		dataHolder[i].SendSurveyResponseQuery(*surveyID, []lib.ClientClearResponse{{nil, sliceGrp, aggr}}, el.Aggregate, 1)

		//compute expected results
		_, ok := expectedResults[grp]
		if ok {
			for ind, v := range expectedResults[grp] {
				expectedResults[grp][ind] = v + aggr[ind]
			}
		} else {
			expectedResults[grp] = aggr
		}
	}

	grpClear, grp, aggr, err := client.SendGetSurveyResultsQuery(*surveyID)

	if err != nil {
		t.Fatal("Service could not output the results.")
	}

	log.Lvl1("Service output:")
	var tabVerify [][]int64
	tabVerify = *grp

	for i := range tabVerify {
		log.Lvl1(i, ")", (*grpClear)[i], (*grp)[i], "->", (*aggr)[i])

		//convert from slice to tab in order to test the values
		grpTab := [numberGrpAttr]int64{}
		for ind, v := range (tabVerify)[i] {
			grpTab[ind] = v
		}
		data, ok := expectedResults[grpTab]
		if !ok || !reflect.DeepEqual(data, (*aggr)[i]) {
			t.Error("Not expected results, got ", (*aggr)[i], " when expected ", data)
		}
	}
}

// Only clear grouping attributes
func TestServiceOnlyClearGrpAttr(t *testing.T) {
	log.LLvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")

	log.SetDebugVisible(2)
	local := onet.NewLocalTest()
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(5, true)
	defer local.CloseAll()

	// Send a request to the service
	client := services.NewMedcoClient(el.List[0])

	surveyDesc := lib.SurveyDescription{GroupingAttributesClearCount: numberGrpAttr, GroupingAttributesEncCount: 0, AggregatingAttributesCount: numberAttr}

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	for _, server := range el.List {
		nbrDPs[server.String()] = 2 // 2 DPs for each server
	}

	surveyID, _, err := client.SendSurveyCreationQuery(el, lib.SurveyID(""), lib.SurveyID(""), surveyDesc, proofsService, false, nil, nil, nil, nbrDPs, 0)

	if err != nil {
		t.Fatal("Service did not start.")
	}

	//save values in a map to verify them at the end
	expectedResults := make(map[[numberGrpAttr]int64][]int64)
	log.Lvl1("Sending response data... ")
	dataHolder := make([]*services.API, 10)
	for i := 0; i < len(dataHolder); i++ {
		dataHolder[i] = services.NewMedcoClient(el.List[i%5])
		grp := [numberGrpAttr]int64{}
		aggr := make([]int64, 10)
		grp[0] = int64(i % 4)
		aggr[i] = 3

		//convert tab in slice (was a tab only for the test)
		sliceGrp := make([]int64, numberGrpAttr)
		for i, v := range grp {
			if i == 0 {
				sliceGrp = []int64{v}
			} else {
				sliceGrp = append(sliceGrp, v)
			}
		}

		dataHolder[i].SendSurveyResponseQuery(*surveyID, []lib.ClientClearResponse{{sliceGrp, nil, aggr}}, el.Aggregate, 1)

		//compute expected results
		_, ok := expectedResults[grp]
		if ok {
			for ind, v := range expectedResults[grp] {
				expectedResults[grp][ind] = v + aggr[ind]
			}
		} else {
			expectedResults[grp] = aggr
		}
	}

	grpClear, grp, aggr, err := client.SendGetSurveyResultsQuery(*surveyID)

	if err != nil {
		t.Fatal("Service could not output the results.")
	}

	log.Lvl1("Service output:")
	var tabVerify [][]int64
	tabVerify = *grpClear

	for i := range tabVerify {
		log.Lvl1(i, ")", (*grpClear)[i], (*grp)[i], "->", (*aggr)[i])

		//convert from slice to tab in order to test the values
		grpTab := [numberGrpAttr]int64{}
		for ind, v := range (tabVerify)[i] {
			grpTab[ind] = v
		}
		data, ok := expectedResults[grpTab]
		if !ok || !reflect.DeepEqual(data, (*aggr)[i]) {
			t.Error("Not expected results, got ", (*aggr)[i], " when expected ", data)
		}
	}
}

// Clear and encrypted grouping attributes
func TestServiceClearAndEncGrpAttr(t *testing.T) {
	log.LLvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest()
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(5, true)
	defer local.CloseAll()

	// Send a request to the service
	client := services.NewMedcoClient(el.List[0])

	surveyDesc := lib.SurveyDescription{GroupingAttributesClearCount: numberGrpAttr, GroupingAttributesEncCount: 1, AggregatingAttributesCount: numberAttr}

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	for _, server := range el.List {
		nbrDPs[server.String()] = 2 // 2 DPs for each server
	}

	surveyID, _, err := client.SendSurveyCreationQuery(el, lib.SurveyID(""), lib.SurveyID(""), surveyDesc, proofsService, false, nil, nil, nil, nbrDPs, 0)

	if err != nil {
		t.Fatal("Service did not start.")
	}

	//save values in a map to verify them at the end
	expectedResults := make(map[[numberGrpAttr + 1]int64][]int64)
	log.Lvl1("Sending response data... ")
	dataHolder := make([]*services.API, 10)
	for i := 0; i < len(dataHolder); i++ {
		dataHolder[i] = services.NewMedcoClient(el.List[i%5])
		grp := [numberGrpAttr + 1]int64{}
		aggr := make([]int64, 10)
		grp[0] = int64(i % 4)
		aggr[i] = 3

		//convert tab in slice (was a tab only for the test)
		sliceGrp := make([]int64, numberGrpAttr)
		for i, v := range grp {
			if i == 0 {
				sliceGrp = []int64{v}
			} else {
				sliceGrp = append(sliceGrp, v)
			}
		}

		valueClear := 0
		if sliceGrp[0] == 1 {
			valueClear = i
		}

		dataHolder[i].SendSurveyResponseQuery(*surveyID, []lib.ClientClearResponse{{[]int64{int64(valueClear)}, sliceGrp, aggr}}, el.Aggregate, 1)

		grp[numberGrpAttr] = int64(valueClear)
		//compute expected results
		_, ok := expectedResults[grp]
		if ok {
			for ind, v := range expectedResults[grp] {

				expectedResults[grp][ind] = v + aggr[ind]
			}
		} else {
			expectedResults[grp] = aggr
		}
	}
	grpClear, grp, aggr, err := client.SendGetSurveyResultsQuery(*surveyID)

	if err != nil {
		t.Fatal("Service could not output the results.")
	}

	log.Lvl1("Service output:")
	var tabVerify [][]int64
	tabVerify = *grp

	for i := range tabVerify {
		log.Lvl1(i, ")", (*grpClear)[i], (*grp)[i][:len((*grp)[i])-1], "->", (*aggr)[i])

		//convert from slice to tab in order to test the values
		grpTab := [numberGrpAttr + 1]int64{}
		for ind, v := range (tabVerify)[i] {
			grpTab[ind] = v
		}
		grpTab[numberGrpAttr] = (*grpClear)[i][0]
		data, ok := expectedResults[grpTab]
		if !ok || !reflect.DeepEqual(data, (*aggr)[i]) {
			t.Error("Not expected results, got ", (*aggr)[i], " when expected ", data)
		}
	}
}

// TEST BATCH 2 -> different number of DPs
//______________________________________________________________________________________________________________________

// Servers with no DPs
func TestAllServersNoDPs(t *testing.T) {
	log.LLvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest()
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(5, true)
	defer local.CloseAll()

	// Send a request to the service
	client := services.NewMedcoClient(el.List[0])

	surveyDesc := lib.SurveyDescription{GroupingAttributesClearCount: numberGrpAttr, GroupingAttributesEncCount: 1, AggregatingAttributesCount: numberAttr}

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	for i, server := range el.List {
		if i < 2 {
			nbrDPs[server.String()] = 5 // 5 DPs for the first 2 servers
		} else {
			nbrDPs[server.String()] = 0 // 0 DP for the remaining 3 servers
		}
	}

	surveyID, _, err := client.SendSurveyCreationQuery(el, lib.SurveyID(""), lib.SurveyID(""), surveyDesc, proofsService, false, nil, nil, nil, nbrDPs, 0)
	if err != nil {
		t.Fatal("Service did not start.")
	}

	//save values in a map to verify them at the end
	expectedResults := make(map[[numberGrpAttr + 1]int64][]int64)
	log.Lvl1("Sending response data... ")
	dataHolder := make([]*services.API, 10)
	for i := 0; i < len(dataHolder); i++ {
		dataHolder[i] = services.NewMedcoClient(el.List[i%2])
		grp := [numberGrpAttr + 1]int64{}
		aggr := make([]int64, 10)
		grp[0] = int64(i % 4)
		aggr[i] = 3

		//convert tab in slice (was a tab only for the test)
		sliceGrp := make([]int64, numberGrpAttr)
		for i, v := range grp {
			if i == 0 {
				sliceGrp = []int64{v}
			} else {
				sliceGrp = append(sliceGrp, v)
			}
		}

		valueClear := 0
		if sliceGrp[0] == 1 {
			valueClear = i
		}

		dataHolder[i].SendSurveyResponseQuery(*surveyID, []lib.ClientClearResponse{{[]int64{int64(valueClear)}, sliceGrp, aggr}}, el.Aggregate, 1)

		grp[numberGrpAttr] = int64(valueClear)

		_, ok := expectedResults[grp]
		if ok {
			for ind, v := range expectedResults[grp] {

				expectedResults[grp][ind] = v + aggr[ind]
			}
		} else {
			expectedResults[grp] = aggr
		}
	}
	grpClear, grp, aggr, err := client.SendGetSurveyResultsQuery(*surveyID)

	if err != nil {
		t.Fatal("Service could not output the results.")
	}

	log.Lvl1("Service output:")
	var tabVerify [][]int64
	tabVerify = *grp

	for i := range tabVerify {
		log.Lvl1(i, ")", (*grpClear)[i], (*grp)[i][:len((*grp)[i])-1], "->", (*aggr)[i])

		//convert from slice to tab in order to test the values
		grpTab := [numberGrpAttr + 1]int64{}
		for ind, v := range (tabVerify)[i] {
			grpTab[ind] = v
		}
		grpTab[numberGrpAttr] = (*grpClear)[i][0]
		data, ok := expectedResults[grpTab]
		if !ok || !reflect.DeepEqual(data, (*aggr)[i]) {
			t.Error("Not expected results, got ", (*aggr)[i], " when expected ", data)
		}
	}
}

// Servers with a different number of DPs
func TestAllServersRandomDPs(t *testing.T) {
	log.LLvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest()
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(5, true)
	defer local.CloseAll()

	// Send a request to the service
	client := services.NewMedcoClient(el.List[0])

	surveyDesc := lib.SurveyDescription{GroupingAttributesClearCount: numberGrpAttr,  GroupingAttributesEncCount: 1, AggregatingAttributesCount: numberAttr}

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	nbrDPs[el.List[0].String()] = 0
	nbrDPs[el.List[1].String()] = 2
	nbrDPs[el.List[2].String()] = 1
	nbrDPs[el.List[3].String()] = 3
	nbrDPs[el.List[4].String()] = 4

	surveyID, _, err := client.SendSurveyCreationQuery(el, lib.SurveyID(""),  lib.SurveyID(""), surveyDesc, proofsService, false, nil, nil, nil, nbrDPs, 0)
	if err != nil {
		t.Fatal("Service did not start.")
	}

	//save values in a map to verify them at the end
	expectedResults := make(map[[numberGrpAttr + 1]int64][]int64)
	log.Lvl1("Sending response data... ")
	dataHolder := make([]*services.API, 10)
	for i := 0; i < len(dataHolder); i++ {
		if i < 2 {
			dataHolder[i] = services.NewMedcoClient(el.List[1])
		} else if i == 2 {
			dataHolder[i] = services.NewMedcoClient(el.List[2])
		} else if i < 6 {
			dataHolder[i] = services.NewMedcoClient(el.List[3])
		} else {
			dataHolder[i] = services.NewMedcoClient(el.List[4])
		}

		grp := [numberGrpAttr + 1]int64{}
		aggr := make([]int64, 10)
		grp[0] = int64(i % 4)
		aggr[i] = 3

		//convert tab in slice (was a tab only for the test)
		sliceGrp := make([]int64, numberGrpAttr)
		for i, v := range grp {
			if i == 0 {
				sliceGrp = []int64{v}
			} else {
				sliceGrp = append(sliceGrp, v)
			}
		}

		valueClear := 0
		if sliceGrp[0] == 1 {
			valueClear = i
		}

		dataHolder[i].SendSurveyResponseQuery(*surveyID, []lib.ClientClearResponse{{[]int64{int64(valueClear)}, sliceGrp, aggr}}, el.Aggregate, 1)

		grp[numberGrpAttr] = int64(valueClear)
		//compute expected results
		_, ok := expectedResults[grp]
		if ok {
			for ind, v := range expectedResults[grp] {

				expectedResults[grp][ind] = v + aggr[ind]
			}
		} else {
			expectedResults[grp] = aggr
		}
	}
	grpClear, grp, aggr, err := client.SendGetSurveyResultsQuery(*surveyID)

	if err != nil {
		t.Fatal("Service could not output the results.")
	}

	log.Lvl1("Service output:")
	var tabVerify [][]int64
	tabVerify = *grp

	for i := range tabVerify {
		log.Lvl1(i, ")", (*grpClear)[i], (*grp)[i][:len((*grp)[i])-1], "->", (*aggr)[i])

		//convert from slice to tab in order to test the values
		grpTab := [numberGrpAttr + 1]int64{}
		for ind, v := range (tabVerify)[i] {
			grpTab[ind] = v
		}
		grpTab[numberGrpAttr] = (*grpClear)[i][0]
		data, ok := expectedResults[grpTab]
		if !ok || !reflect.DeepEqual(data, (*aggr)[i]) {
			t.Error("Not expected results, got ", (*aggr)[i], " when expected ", data)
		}
	}

}
