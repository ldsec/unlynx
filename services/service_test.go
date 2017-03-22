package services_test

import (
	"testing"

	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/JoaoAndreSa/MedCo/services"

	"gopkg.in/dedis/onet.v1/log"

	"gopkg.in/dedis/onet.v1"
	"os"
	"reflect"
	"strconv"
)

// numberGrpAttr is the number of group attributes.
const numberGrpAttr = 3

// numberAttr is the number of attributes.
const numberAttr = 2

const proofsService = true

func TestMain(m *testing.M) {
	log.MainTest(m)
}

// TEST BATCH 1 -> encrypted or/and non-encrypted grouping attributes

//______________________________________________________________________________________________________________________
/// Only clear where and group by attributes + tests shuffling if 1 element -> add a dummy one
func TestServiceClearAttr(t *testing.T) {
	log.LLvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest()
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(5, true)
	defer local.CloseAll()

	// Send a request to the service
	client := services.NewMedcoClient(el.List[0], strconv.Itoa(0))

	sum := []string{"s1", "s2"}
	count := false
	whereQueryValues := []lib.WhereQueryAttribute{{Name: "w1", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w2", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w3", Value: *lib.EncryptInt(el.Aggregate, 1)}} // v1, v3 and v5
	predicate := "(v0 == v1 || v2 == v3) && v4 == v5"
	groupBy := []string{"g1", "g2", "g3"}

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	for _, server := range el.List {
		nbrDPs[server.String()] = 2 // 2 DPs for each server
	}

	surveyID, _, err := client.SendSurveyCreationQuery(el, lib.SurveyID("testSurvey"), lib.SurveyID(""), sum, count, whereQueryValues, predicate, groupBy, nil, nil, nbrDPs, 0, proofsService, false)

	if err != nil {
		t.Fatal("Service did not start.", err)
	}

	//save values in a map to verify them at the end
	expectedResults := make(map[[numberGrpAttr]int64][]int64)
	log.Lvl1("Sending response data... ")
	dataHolder := make([]*services.API, 10)
	for i := 0; i < len(dataHolder); i++ {
		dataHolder[i] = services.NewMedcoClient(el.List[i%5], strconv.Itoa(i+1))
		grp := [numberGrpAttr]int64{}
		aggr := make(map[string]int64, numberAttr)

		grp[0] = int64(i % 4)
		aggr["s"+strconv.Itoa(i+1)] = 3

		//convert tab in slice (was a tab only for the test)
		val := int64(1)
		if i == 2 {
			val = int64(2)
		}
		sliceWhere := make(map[string]int64, numberGrpAttr)
		for j := range grp {
			sliceWhere["w"+strconv.Itoa(j+1)] = int64(val)

		}

		sliceGrp := make(map[string]int64, numberGrpAttr)
		for j := range grp {
			sliceGrp["g"+strconv.Itoa(j+1)] = int64(j)

		}
		sliceGrp1 := make(map[string]int64, numberGrpAttr)
		for j := range grp {
			sliceGrp1["g"+strconv.Itoa(j+1)] = int64(j + 1)

		}

		aggr = make(map[string]int64, numberAttr)
		for j := 0; j < numberAttr; j++ {
			aggr["s"+strconv.Itoa(j+1)] = int64(j)
		}

		//responses:= []lib.DpClearResponse{{WhereClear: sliceWhere, GroupByClear: sliceGrp, AggregatingAttributesEnc: aggr},{WhereClear: sliceWhere, GroupByClear: sliceGrp, AggregatingAttributesEnc: aggr},{WhereClear: sliceWhere, GroupByClear: sliceGrp1, AggregatingAttributesEnc: aggr}}
		responses := []lib.DpClearResponse{{WhereClear: sliceWhere, GroupByClear: sliceGrp, AggregatingAttributesEnc: aggr}, {WhereClear: sliceWhere, GroupByClear: sliceGrp, AggregatingAttributesEnc: aggr}}

		log.LLvl1(responses)
		dataHolder[i].SendSurveyResponseQuery(*surveyID, responses, el.Aggregate, 1, count)

	}

	expectedResults[[3]int64{0, 1, 2}] = []int64{0, 18}
	//expectedResults[[3]int64{1,2,3}] = []int64{0,9}
	grp, aggr, err := client.SendSurveyResultsQuery(*surveyID)

	if err != nil {
		t.Fatal("Service could not output the results.")
	}

	log.Lvl1("Service output:")
	var tabVerify [][]int64
	tabVerify = *grp
	for i := range tabVerify {
		log.Lvl1(i, ")", (*grp)[i], "->", (*aggr)[i])

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

//______________________________________________________________________________________________________________________
/// Only encrypted where and clear group by attributes
func TestServiceClearGrpEncWhereAttr(t *testing.T) {
	log.LLvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest()
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(5, true)
	defer local.CloseAll()

	// Send a request to the service
	client := services.NewMedcoClient(el.List[0], strconv.Itoa(0))

	sum := []string{"s1", "s2"}
	count := false
	whereQueryValues := []lib.WhereQueryAttribute{{Name: "w1", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w2", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w3", Value: *lib.EncryptInt(el.Aggregate, 1)}} // v1, v3 and v5
	predicate := "(v0 == v1 || v2 == v3) && v4 == v5"
	groupBy := []string{"g1", "g2", "g3"}

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	for _, server := range el.List {
		nbrDPs[server.String()] = 2 // 2 DPs for each server
	}

	surveyID, _, err := client.SendSurveyCreationQuery(el, lib.SurveyID("testSurvey"), lib.SurveyID(""), sum, count, whereQueryValues, predicate, groupBy, nil, nil, nbrDPs, 0, proofsService, false)

	if err != nil {
		t.Fatal("Service did not start.", err)
	}

	//save values in a map to verify them at the end
	expectedResults := make(map[[numberGrpAttr]int64][]int64)
	log.Lvl1("Sending response data... ")
	dataHolder := make([]*services.API, 10)
	for i := 0; i < len(dataHolder); i++ {
		dataHolder[i] = services.NewMedcoClient(el.List[i%5], strconv.Itoa(i+1))
		grp := [numberGrpAttr]int64{}
		aggr := make(map[string]int64, numberAttr)

		grp[0] = int64(i % 4)
		aggr["s"+strconv.Itoa(i+1)] = 3

		//convert tab in slice (was a tab only for the test)
		val := int64(1)
		if i == 2 {
			val = int64(2)
		}
		sliceWhere := make(map[string]int64, numberGrpAttr)
		for j := range grp {
			sliceWhere["w"+strconv.Itoa(j+1)] = int64(val)
		}

		sliceGrp := make(map[string]int64, numberGrpAttr)
		for j := range grp {
			sliceGrp["g"+strconv.Itoa(j+1)] = int64(j)
		}
		sliceGrp1 := make(map[string]int64, numberGrpAttr)
		for j := range grp {
			sliceGrp1["g"+strconv.Itoa(j+1)] = int64(j + 1)
		}

		aggr = make(map[string]int64, numberAttr)
		for j := 0; j < numberAttr; j++ {
			aggr["s"+strconv.Itoa(j+1)] = int64(j)
		}

		responses := []lib.DpClearResponse{{WhereEnc: sliceWhere, GroupByClear: sliceGrp, AggregatingAttributesEnc: aggr}, {WhereEnc: sliceWhere, GroupByClear: sliceGrp, AggregatingAttributesEnc: aggr}, {WhereEnc: sliceWhere, GroupByClear: sliceGrp1, AggregatingAttributesEnc: aggr}}
		dataHolder[i].SendSurveyResponseQuery(*surveyID, responses, el.Aggregate, 1, count)
	}

	expectedResults[[3]int64{0, 1, 2}] = []int64{0, 18}
	expectedResults[[3]int64{1, 2, 3}] = []int64{0, 9}
	grp, aggr, err := client.SendSurveyResultsQuery(*surveyID)

	if err != nil {
		t.Fatal("Service could not output the results.")
	}

	log.Lvl1("Service output:")
	var tabVerify [][]int64
	tabVerify = *grp
	for i := range tabVerify {
		log.Lvl1(i, ")", (*grp)[i], "->", (*aggr)[i])

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

//______________________________________________________________________________________________________________________
/// Only clear where and encrypted group by attributes
func TestServiceEncGrpClearWhereAttr(t *testing.T) {
	log.LLvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest()
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(5, true)
	defer local.CloseAll()

	// Send a request to the service
	client := services.NewMedcoClient(el.List[0], strconv.Itoa(0))

	sum := []string{"s1", "s2"}
	count := false
	whereQueryValues := []lib.WhereQueryAttribute{{Name: "w1", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w2", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w3", Value: *lib.EncryptInt(el.Aggregate, 1)}} // v1, v3 and v5
	predicate := "(v0 == v1 || v2 == v3) && v4 == v5"
	groupBy := []string{"g1", "g2", "g3"}

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	for _, server := range el.List {
		nbrDPs[server.String()] = 2 // 2 DPs for each server
	}

	surveyID, _, err := client.SendSurveyCreationQuery(el, lib.SurveyID("testSurvey"), lib.SurveyID(""), sum, count, whereQueryValues, predicate, groupBy, nil, nil, nbrDPs, 0, proofsService, false)

	if err != nil {
		t.Fatal("Service did not start.", err)
	}

	//save values in a map to verify them at the end
	expectedResults := make(map[[numberGrpAttr]int64][]int64)
	log.Lvl1("Sending response data... ")
	dataHolder := make([]*services.API, 10)
	for i := 0; i < len(dataHolder); i++ {
		dataHolder[i] = services.NewMedcoClient(el.List[i%5], strconv.Itoa(i+1))
		grp := [numberGrpAttr]int64{}
		aggr := make(map[string]int64, numberAttr)

		grp[0] = int64(i % 4)
		aggr["s"+strconv.Itoa(i+1)] = 3

		//convert tab in slice (was a tab only for the test)
		val := int64(1)
		if i == 2 {
			val = int64(2)
		}
		sliceWhere := make(map[string]int64, numberGrpAttr)
		for j := range grp {
			sliceWhere["w"+strconv.Itoa(j+1)] = int64(val)
		}

		sliceGrp := make(map[string]int64, numberGrpAttr)
		for j := range grp {
			sliceGrp["g"+strconv.Itoa(j+1)] = int64(j)
		}

		sliceGrp1 := make(map[string]int64, numberGrpAttr)
		for j := range grp {
			sliceGrp1["g"+strconv.Itoa(j+1)] = int64(j + 1)
		}

		aggr = make(map[string]int64, numberAttr)
		for j := 0; j < numberAttr; j++ {
			aggr["s"+strconv.Itoa(j+1)] = int64(j)
		}

		responses := []lib.DpClearResponse{{WhereClear: sliceWhere, GroupByEnc: sliceGrp, AggregatingAttributesEnc: aggr}, {WhereClear: sliceWhere, GroupByEnc: sliceGrp1, AggregatingAttributesEnc: aggr}}
		dataHolder[i].SendSurveyResponseQuery(*surveyID, responses, el.Aggregate, 1, count)
	}

	expectedResults[[3]int64{0, 1, 2}] = []int64{0, 9}
	expectedResults[[3]int64{1, 2, 3}] = []int64{0, 9}
	grp, aggr, err := client.SendSurveyResultsQuery(*surveyID)

	if err != nil {
		t.Fatal("Service could not output the results.")
	}

	log.Lvl1("Service output:")
	var tabVerify [][]int64
	tabVerify = *grp
	for i := range tabVerify {
		log.Lvl1(i, ")", (*grp)[i], "->", (*aggr)[i])

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

//______________________________________________________________________________________________________________________
/// Only encrypted attributes
func TestServiceEncGrpAndWhereAttr(t *testing.T) {
	log.LLvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest()
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(5, true)
	defer local.CloseAll()

	// Send a request to the service
	client := services.NewMedcoClient(el.List[0], strconv.Itoa(0))

	sum := []string{"s1", "s2"}
	count := false
	whereQueryValues := []lib.WhereQueryAttribute{{Name: "w1", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w2", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w3", Value: *lib.EncryptInt(el.Aggregate, 1)}} // v1, v3 and v5
	predicate := "(v0 == v1 || v2 == v3) && v4 == v5"
	groupBy := []string{"g1", "g2", "g3"}

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	for _, server := range el.List {
		nbrDPs[server.String()] = 2 // 2 DPs for each server
	}

	surveyID, _, err := client.SendSurveyCreationQuery(el, lib.SurveyID("testSurvey"), lib.SurveyID(""), sum, count, whereQueryValues, predicate, groupBy, nil, nil, nbrDPs, 0, proofsService, false)

	if err != nil {
		t.Fatal("Service did not start.", err)
	}

	//save values in a map to verify them at the end
	expectedResults := make(map[[numberGrpAttr]int64][]int64)
	log.Lvl1("Sending response data... ")
	dataHolder := make([]*services.API, 10)
	for i := 0; i < len(dataHolder); i++ {
		dataHolder[i] = services.NewMedcoClient(el.List[i%5], strconv.Itoa(i+1))
		grp := [numberGrpAttr]int64{}
		aggr := make(map[string]int64, numberAttr)

		grp[0] = int64(i % 4)
		aggr["s"+strconv.Itoa(i+1)] = 3

		//convert tab in slice (was a tab only for the test)
		val := int64(1)
		if i == 2 {
			val = int64(2)
		}
		sliceWhere := make(map[string]int64, numberGrpAttr)
		for j := range grp {
			sliceWhere["w"+strconv.Itoa(j+1)] = int64(val)

		}

		sliceGrp := make(map[string]int64, numberGrpAttr)
		for j := range grp {
			sliceGrp["g"+strconv.Itoa(j+1)] = int64(j)

		}
		sliceGrp1 := make(map[string]int64, numberGrpAttr)
		for j := range grp {
			sliceGrp1["g"+strconv.Itoa(j+1)] = int64(j + 1)

		}

		aggr = make(map[string]int64, numberAttr)
		for j := 0; j < numberAttr; j++ {
			aggr["s"+strconv.Itoa(j+1)] = int64(j)

		}

		responses := []lib.DpClearResponse{{WhereEnc: sliceWhere, GroupByEnc: sliceGrp, AggregatingAttributesEnc: aggr}, {WhereEnc: sliceWhere, GroupByEnc: sliceGrp1, AggregatingAttributesEnc: aggr}}
		dataHolder[i].SendSurveyResponseQuery(*surveyID, responses, el.Aggregate, 1, count)
	}

	expectedResults[[3]int64{0, 1, 2}] = []int64{0, 9}
	expectedResults[[3]int64{1, 2, 3}] = []int64{0, 9}
	grp, aggr, err := client.SendSurveyResultsQuery(*surveyID)

	if err != nil {
		t.Fatal("Service could not output the results.")
	}

	log.Lvl1("Service output:")
	var tabVerify [][]int64
	tabVerify = *grp
	for i := range tabVerify {
		log.Lvl1(i, ")", (*grp)[i], "->", (*aggr)[i])

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

//______________________________________________________________________________________________________________________
/// Only encrypted attributes
func TestServiceEverything(t *testing.T) {
	log.LLvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest()
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(5, true)
	defer local.CloseAll()

	// Send a request to the service
	client := services.NewMedcoClient(el.List[0], strconv.Itoa(0))

	sum := []string{"s1", "s2"}
	count := false
	whereQueryValues := []lib.WhereQueryAttribute{{Name: "w1", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w2", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w3", Value: *lib.EncryptInt(el.Aggregate, 1)}} // v1, v3 and v5
	predicate := "(v0 == v1 || v2 == v3) && v4 == v5"
	groupBy := []string{"g1", "g2", "g3"}

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	for _, server := range el.List {
		nbrDPs[server.String()] = 2 // 2 DPs for each server
	}

	surveyID, _, err := client.SendSurveyCreationQuery(el, lib.SurveyID("testSurvey"), lib.SurveyID(""), sum, count, whereQueryValues, predicate, groupBy, nil, nil, nbrDPs, 0, proofsService, false)

	if err != nil {
		t.Fatal("Service did not start.", err)
	}

	//save values in a map to verify them at the end
	expectedResults := make(map[[numberGrpAttr]int64][]int64)
	log.Lvl1("Sending response data... ")
	dataHolder := make([]*services.API, 10)
	for i := 0; i < len(dataHolder); i++ {
		dataHolder[i] = services.NewMedcoClient(el.List[i%5], strconv.Itoa(i+1))
		grp := [numberGrpAttr]int64{}
		aggr := make(map[string]int64, numberAttr)

		grp[0] = int64(i % 4)
		aggr["s"+strconv.Itoa(i+1)] = 3

		//convert tab in slice (was a tab only for the test)
		val := int64(1)
		if i == 2 {
			val = int64(2)
		}
		sliceWhere := make(map[string]int64, numberGrpAttr)
		for j := range grp {
			sliceWhere["w"+strconv.Itoa(j+1)] = int64(val)
		}

		sliceGrp := make(map[string]int64, numberGrpAttr)
		for j := range grp {
			sliceGrp["g"+strconv.Itoa(j+1)] = int64(j)
		}
		sliceGrp1 := make(map[string]int64, numberGrpAttr)
		for j := range grp {
			sliceGrp1["g"+strconv.Itoa(j+1)] = int64(j + 1)
		}

		aggr = make(map[string]int64, numberAttr)
		for j := 0; j < numberAttr; j++ {
			aggr["s"+strconv.Itoa(j+1)] = int64(j)
		}

		responses := []lib.DpClearResponse{{WhereClear: sliceWhere, WhereEnc: sliceWhere, GroupByClear: sliceGrp, GroupByEnc: sliceGrp, AggregatingAttributesEnc: aggr}, {WhereClear: sliceWhere, WhereEnc: sliceWhere, GroupByClear: sliceGrp, GroupByEnc: sliceGrp1, AggregatingAttributesEnc: aggr}}
		dataHolder[i].SendSurveyResponseQuery(*surveyID, responses, el.Aggregate, 1, count)
	}

	expectedResults[[3]int64{0, 1, 2}] = []int64{0, 9}
	expectedResults[[3]int64{1, 2, 3}] = []int64{0, 9}
	grp, aggr, err := client.SendSurveyResultsQuery(*surveyID)

	if err != nil {
		t.Fatal("Service could not output the results.")
	}

	log.Lvl1("Service output:")
	var tabVerify [][]int64
	tabVerify = *grp
	for i := range tabVerify {
		log.Lvl1(i, ")", (*grp)[i], "->", (*aggr)[i])

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

// Only encrypted attributes with count
func TestServiceEncGrpAndWhereAttrWithCount(t *testing.T) {
	log.LLvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest()
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(5, true)
	defer local.CloseAll()

	// Send a request to the service
	client := services.NewMedcoClient(el.List[0], strconv.Itoa(0))

	sum := []string{"s1", "s2", "count"}
	count := true
	whereQueryValues := []lib.WhereQueryAttribute{{Name: "w1", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w2", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w3", Value: *lib.EncryptInt(el.Aggregate, 1)}} // v1, v3 and v5
	predicate := "(v0 == v1 || v2 == v3) && v4 == v5"
	groupBy := []string{"g1", "g2", "g3"}

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	for _, server := range el.List {
		nbrDPs[server.String()] = 2 // 2 DPs for each server
	}

	surveyID, _, err := client.SendSurveyCreationQuery(el, lib.SurveyID("testSurvey"), lib.SurveyID(""), sum, count, whereQueryValues, predicate, groupBy, nil, nil, nbrDPs, 0, proofsService, false)

	if err != nil {
		t.Fatal("Service did not start.", err)
	}

	//save values in a map to verify them at the end
	expectedResults := make(map[[numberGrpAttr]int64][]int64)
	log.Lvl1("Sending response data... ")
	dataHolder := make([]*services.API, 10)
	for i := 0; i < len(dataHolder); i++ {
		dataHolder[i] = services.NewMedcoClient(el.List[i%5], strconv.Itoa(i+1))
		grp := [numberGrpAttr]int64{}
		aggr := make(map[string]int64, numberAttr)

		grp[0] = int64(i % 4)
		aggr["s"+strconv.Itoa(i+1)] = 3

		//convert tab in slice (was a tab only for the test)
		val := int64(1)
		if i == 2 {
			val = int64(2)
		}
		sliceWhere := make(map[string]int64, numberGrpAttr)
		for j := range grp {
			sliceWhere["w"+strconv.Itoa(j+1)] = int64(val)
		}

		sliceGrp := make(map[string]int64, numberGrpAttr)
		for j := range grp {
			sliceGrp["g"+strconv.Itoa(j+1)] = int64(j)
		}
		sliceGrp1 := make(map[string]int64, numberGrpAttr)
		for j := range grp {
			sliceGrp1["g"+strconv.Itoa(j+1)] = int64(j + 1)
		}

		aggr = make(map[string]int64, numberAttr)
		for j := 0; j < numberAttr; j++ {
			aggr["s"+strconv.Itoa(j+1)] = int64(j)
		}

		responses := []lib.DpClearResponse{{WhereClear: sliceWhere, WhereEnc: sliceWhere, GroupByClear: sliceGrp, GroupByEnc: sliceGrp, AggregatingAttributesEnc: aggr}, {WhereClear: sliceWhere, WhereEnc: sliceWhere, GroupByClear: sliceGrp, GroupByEnc: sliceGrp1, AggregatingAttributesEnc: aggr}}
		dataHolder[i].SendSurveyResponseQuery(*surveyID, responses, el.Aggregate, 1, count)
	}

	expectedResults[[3]int64{0, 1, 2}] = []int64{0, 9, 9}
	expectedResults[[3]int64{1, 2, 3}] = []int64{0, 9, 9}
	grp, aggr, err := client.SendSurveyResultsQuery(*surveyID)

	if err != nil {
		t.Fatal("Service could not output the results.")
	}

	log.Lvl1("Service output:")
	var tabVerify [][]int64
	tabVerify = *grp
	for i := range tabVerify {
		log.Lvl1(i, ")", (*grp)[i], "->", (*aggr)[i])

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
	client := services.NewMedcoClient(el.List[0], strconv.Itoa(0))

	sum := []string{"s1", "s2"}
	count := false
	whereQueryValues := []lib.WhereQueryAttribute{{Name: "w1", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w2", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w3", Value: *lib.EncryptInt(el.Aggregate, 1)}} // v1, v3 and v5
	predicate := "(v0 == v1 || v2 == v3) && v4 == v5"
	groupBy := []string{"g1", "g2", "g3"}

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	for i, server := range el.List {
		if i < 2 {
			nbrDPs[server.String()] = 5 // 5 DPs for the first 2 servers
		} else {
			nbrDPs[server.String()] = 0 // 0 DP for the remaining 3 servers
		}
	}

	surveyID, _, err := client.SendSurveyCreationQuery(el, lib.SurveyID("testSurvey"), lib.SurveyID(""), sum, count, whereQueryValues, predicate, groupBy, nil, nil, nbrDPs, 0, proofsService, false)

	if err != nil {
		t.Fatal("Service did not start.")
	}

	//save values in a map to verify them at the end
	expectedResults := make(map[[numberGrpAttr]int64][]int64)
	log.Lvl1("Sending response data... ")
	dataHolder := make([]*services.API, 10)
	for i := 0; i < len(dataHolder); i++ {
		dataHolder[i] = services.NewMedcoClient(el.List[i%2], strconv.Itoa(i+1))
		grp := [numberGrpAttr]int64{}
		aggr := make(map[string]int64, numberAttr)

		grp[0] = int64(i % 4)
		aggr["s"+strconv.Itoa(i+1)] = 3

		//convert tab in slice (was a tab only for the test)
		val := int64(1)
		if i == 2 {
			val = int64(2)
		}
		sliceWhere := make(map[string]int64, numberGrpAttr)
		for j := range grp {
			sliceWhere["w"+strconv.Itoa(j+1)] = int64(val)
		}

		sliceGrp := make(map[string]int64, numberGrpAttr)
		for j := range grp {
			sliceGrp["g"+strconv.Itoa(j+1)] = int64(j)
		}
		sliceGrp1 := make(map[string]int64, numberGrpAttr)
		for j := range grp {
			sliceGrp1["g"+strconv.Itoa(j+1)] = int64(j + 1)
		}

		aggr = make(map[string]int64, numberAttr)
		for j := 0; j < numberAttr; j++ {
			aggr["s"+strconv.Itoa(j+1)] = int64(j)
		}

		responses := []lib.DpClearResponse{{WhereClear: sliceWhere, WhereEnc: sliceWhere, GroupByClear: sliceGrp, GroupByEnc: sliceGrp, AggregatingAttributesEnc: aggr}, {WhereClear: sliceWhere, WhereEnc: sliceWhere, GroupByClear: sliceGrp, GroupByEnc: sliceGrp1, AggregatingAttributesEnc: aggr}}
		dataHolder[i].SendSurveyResponseQuery(*surveyID, responses, el.Aggregate, 1, count)
	}

	expectedResults[[3]int64{0, 1, 2}] = []int64{0, 9}
	expectedResults[[3]int64{1, 2, 3}] = []int64{0, 9}
	grp, aggr, err := client.SendSurveyResultsQuery(*surveyID)

	if err != nil {
		t.Fatal("Service could not output the results.")
	}

	log.Lvl1("Service output:")
	var tabVerify [][]int64
	tabVerify = *grp
	for i := range tabVerify {
		log.Lvl1(i, ")", (*grp)[i], "->", (*aggr)[i])

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
	client := services.NewMedcoClient(el.List[0], strconv.Itoa(0))

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	nbrDPs[el.List[0].String()] = 0
	nbrDPs[el.List[1].String()] = 2
	nbrDPs[el.List[2].String()] = 1
	nbrDPs[el.List[3].String()] = 3
	nbrDPs[el.List[4].String()] = 4

	sum := []string{"s1", "s2"}
	count := false
	whereQueryValues := []lib.WhereQueryAttribute{{Name: "w1", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w2", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w3", Value: *lib.EncryptInt(el.Aggregate, 1)}} // v1, v3 and v5
	predicate := "(v0 == v1 || v2 == v3) && v4 == v5"
	groupBy := []string{"g1", "g2", "g3"}

	surveyID, _, err := client.SendSurveyCreationQuery(el, lib.SurveyID("testSurvey"), lib.SurveyID(""), sum, count, whereQueryValues, predicate, groupBy, nil, nil, nbrDPs, 0, proofsService, false)

	if err != nil {
		t.Fatal("Service did not start.")
	}

	//save values in a map to verify them at the end
	expectedResults := make(map[[numberGrpAttr]int64][]int64)
	log.Lvl1("Sending response data... ")
	dataHolder := make([]*services.API, 10)
	for i := 0; i < len(dataHolder); i++ {
		if i < 2 {
			dataHolder[i] = services.NewMedcoClient(el.List[1], strconv.Itoa(i+1))
		} else if i == 2 {
			dataHolder[i] = services.NewMedcoClient(el.List[2], strconv.Itoa(i+1))
		} else if i < 6 {
			dataHolder[i] = services.NewMedcoClient(el.List[3], strconv.Itoa(i+1))
		} else {
			dataHolder[i] = services.NewMedcoClient(el.List[4], strconv.Itoa(i+1))
		}

		grp := [numberGrpAttr]int64{}
		aggr := make(map[string]int64, numberAttr)

		grp[0] = int64(i % 4)
		aggr["s"+strconv.Itoa(i+1)] = 3

		//convert tab in slice (was a tab only for the test)
		val := int64(1)
		if i == 2 {
			val = int64(2)
		}
		sliceWhere := make(map[string]int64, numberGrpAttr)
		for j := range grp {
			sliceWhere["w"+strconv.Itoa(j+1)] = int64(val)
		}

		sliceGrp := make(map[string]int64, numberGrpAttr)
		for j := range grp {
			sliceGrp["g"+strconv.Itoa(j+1)] = int64(j)
		}
		sliceGrp1 := make(map[string]int64, numberGrpAttr)
		for j := range grp {
			sliceGrp1["g"+strconv.Itoa(j+1)] = int64(j + 1)
		}

		aggr = make(map[string]int64, numberAttr)
		for j := 0; j < numberAttr; j++ {
			aggr["s"+strconv.Itoa(j+1)] = int64(j)
		}

		responses := []lib.DpClearResponse{{WhereClear: sliceWhere, WhereEnc: sliceWhere, GroupByClear: sliceGrp, GroupByEnc: sliceGrp, AggregatingAttributesEnc: aggr}, {WhereClear: sliceWhere, WhereEnc: sliceWhere, GroupByClear: sliceGrp, GroupByEnc: sliceGrp1, AggregatingAttributesEnc: aggr}}
		dataHolder[i].SendSurveyResponseQuery(*surveyID, responses, el.Aggregate, 1, count)
	}
	expectedResults[[3]int64{0, 1, 2}] = []int64{0, 9}
	expectedResults[[3]int64{1, 2, 3}] = []int64{0, 9}
	grp, aggr, err := client.SendSurveyResultsQuery(*surveyID)

	if err != nil {
		t.Fatal("Service could not output the results.")
	}

	log.Lvl1("Service output:")
	var tabVerify [][]int64
	tabVerify = *grp
	for i := range tabVerify {
		log.Lvl1(i, ")", (*grp)[i], "->", (*aggr)[i])

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

func TestFilteringFunc(t *testing.T) {
	predicate := "(v0 == v1 && v2 == v3) && v4 == v5"
	whereQueryValues := []lib.WhereQueryAttributeTagged{{Name: "age", Value: lib.GroupingKey("1")}, {Name: "salary", Value: lib.GroupingKey("1")}, {Name: "joao", Value: lib.GroupingKey("1")}}
	responsesToFilter := []lib.ProcessResponseDet{{DetTagWhere: []lib.GroupingKey{lib.GroupingKey("1"), lib.GroupingKey("1"), lib.GroupingKey("1")}}, {DetTagWhere: []lib.GroupingKey{lib.GroupingKey("1"), lib.GroupingKey("1"), lib.GroupingKey("2")}}}
	log.LLvl1(predicate)
	log.LLvl1(responsesToFilter)
	log.LLvl1(whereQueryValues)
	log.LLvl1(services.FilterResponses(predicate, whereQueryValues, responsesToFilter))
}
