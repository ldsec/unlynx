package servicesunlynxdefault_test

import (
	"os"
	"reflect"
	"strconv"
	"sync"
	"testing"

	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/services/default"
	"github.com/stretchr/testify/assert"
)

// numberGrpAttr is the number of group attributes.
const numberGrpAttr = 3

// numberAttr is the number of attributes.
const numberAttr = 2

const proofsService = true

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestFilterResponses(t *testing.T) {
	// ****************************************
	// simple predicate
	predicate := "v0 == v1"

	whereAttributes := make([]libunlynx.WhereQueryAttributeTagged, 0)
	whereAttributes = append(whereAttributes, libunlynx.WhereQueryAttributeTagged{Name: "w0", Value: "1"})

	data := make([]libunlynx.ProcessResponseDet, 0)

	// predicate is true
	whereTrue := [1]libunlynx.GroupingKey{libunlynx.GroupingKey("1")}

	// predicate is false
	whereFalse := [1]libunlynx.GroupingKey{libunlynx.GroupingKey("0")}

	data = append(data, libunlynx.ProcessResponseDet{PR: libunlynx.ProcessResponse{}, DetTagGroupBy: "", DetTagWhere: whereTrue[:]})
	data = append(data, libunlynx.ProcessResponseDet{PR: libunlynx.ProcessResponse{}, DetTagGroupBy: "", DetTagWhere: whereFalse[:]})

	result := servicesunlynxdefault.FilterResponses(predicate, whereAttributes, data)

	// 1 result(s) are true
	assert.Equal(t, len(result), 1)

	data = append(data, libunlynx.ProcessResponseDet{PR: libunlynx.ProcessResponse{}, DetTagGroupBy: "", DetTagWhere: whereTrue[:]})

	result = servicesunlynxdefault.FilterResponses(predicate, whereAttributes, data)

	// 2 result(s) are true
	assert.Equal(t, len(result), 2)

	// ****************************************
	// more complex predicate
	predicate = "v0 != v1 || (v2 == v3 && v4 == v5)"

	whereAttributes = make([]libunlynx.WhereQueryAttributeTagged, 0)
	whereAttributes = append(whereAttributes, libunlynx.WhereQueryAttributeTagged{Name: "w0", Value: "27"})
	whereAttributes = append(whereAttributes, libunlynx.WhereQueryAttributeTagged{Name: "w1", Value: "0"})
	whereAttributes = append(whereAttributes, libunlynx.WhereQueryAttributeTagged{Name: "w2", Value: "99"})

	// predicate is true
	whereTrue1 := [3]libunlynx.GroupingKey{libunlynx.GroupingKey("21"), libunlynx.GroupingKey("6"), libunlynx.GroupingKey("0")}
	whereTrue2 := [3]libunlynx.GroupingKey{libunlynx.GroupingKey("27"), libunlynx.GroupingKey("0"), libunlynx.GroupingKey("99")}

	// predicate is false
	whereFalse1 := [3]libunlynx.GroupingKey{libunlynx.GroupingKey("27"), libunlynx.GroupingKey("6"), libunlynx.GroupingKey("0")}

	data = make([]libunlynx.ProcessResponseDet, 0)
	data = append(data, libunlynx.ProcessResponseDet{PR: libunlynx.ProcessResponse{}, DetTagGroupBy: "", DetTagWhere: whereTrue1[:]})
	data = append(data, libunlynx.ProcessResponseDet{PR: libunlynx.ProcessResponse{}, DetTagGroupBy: "", DetTagWhere: whereTrue2[:]})
	data = append(data, libunlynx.ProcessResponseDet{PR: libunlynx.ProcessResponse{}, DetTagGroupBy: "", DetTagWhere: whereFalse1[:]})

	result = servicesunlynxdefault.FilterResponses(predicate, whereAttributes, data)

	// 2 result(s) are true
	assert.Equal(t, len(result), 2)
}

func TestCountDPs(t *testing.T) {
	nbrServer := 7
	nbrElementsPerServer := 3

	mapTest := make(map[string]int64)
	for i := 0; i < nbrServer; i++ {
		mapTest["server"+strconv.Itoa(i)] = int64(nbrElementsPerServer)
	}

	assert.Equal(t, int64(nbrElementsPerServer*nbrServer), servicesunlynxdefault.CountDPs(mapTest))
}

// TEST BATCH 1 -> encrypted or/and non-encrypted grouping attributes

//______________________________________________________________________________________________________________________
/// Only clear where and group by attributes + tests shuffling if 1 element -> add a dummy one
func TestServiceClearAttr(t *testing.T) {
	log.Lvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	local := onet.NewLocalTest(libunlynx.SuiTe)
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(5, true)
	defer local.CloseAll()

	// Send a request to the service
	client := servicesunlynxdefault.NewUnLynxClient(el.List[0], strconv.Itoa(0))

	sum := []string{"s1", "s2"}
	count := false
	whereQueryValues := []libunlynx.WhereQueryAttribute{{Name: "w1", Value: *libunlynx.EncryptInt(el.Aggregate, 1)}, {Name: "w2", Value: *libunlynx.EncryptInt(el.Aggregate, 1)}, {Name: "w3", Value: *libunlynx.EncryptInt(el.Aggregate, 1)}} // v1, v3 and v5
	predicate := "(v0 == v1 || v2 == v3) && v4 == v5"
	groupBy := []string{"g1", "g2", "g3"}

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	for _, server := range el.List {
		nbrDPs[server.String()] = 2 // 2 DPs for each server
	}

	surveyID, err := client.SendSurveyCreationQuery(el, servicesunlynxdefault.SurveyID(""), nil, nbrDPs, proofsService, false, sum, count, whereQueryValues, predicate, groupBy)

	if err != nil {
		t.Fatal("Service did not start.", err)
	}

	//save values in a map to verify them at the end
	expectedResults := make(map[[numberGrpAttr]int64][]int64)
	log.Lvl1("Sending response data... ")
	dataHolder := make([]*servicesunlynxdefault.API, 10)
	for i := 0; i < len(dataHolder); i++ {
		dataHolder[i] = servicesunlynxdefault.NewUnLynxClient(el.List[i%5], strconv.Itoa(i+1))
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
		responses := []libunlynx.DpClearResponse{{WhereClear: sliceWhere, GroupByClear: sliceGrp, AggregatingAttributesEnc: aggr}, {WhereClear: sliceWhere, GroupByClear: sliceGrp, AggregatingAttributesEnc: aggr}}

		log.Lvl1(responses)
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

	if len(tabVerify) == 0 {
		t.Error("Result array should not be empty")
	}
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
	log.Lvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest(libunlynx.SuiTe)
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(5, true)
	defer local.CloseAll()

	// Send a request to the service
	client := servicesunlynxdefault.NewUnLynxClient(el.List[0], strconv.Itoa(0))

	sum := []string{"s1", "s2"}
	count := false
	whereQueryValues := []libunlynx.WhereQueryAttribute{{Name: "w1", Value: *libunlynx.EncryptInt(el.Aggregate, 1)}, {Name: "w2", Value: *libunlynx.EncryptInt(el.Aggregate, 1)}, {Name: "w3", Value: *libunlynx.EncryptInt(el.Aggregate, 1)}} // v1, v3 and v5
	predicate := "(v0 == v1 || v2 == v3) && v4 == v5"
	groupBy := []string{"g1", "g2", "g3"}

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	for _, server := range el.List {
		nbrDPs[server.String()] = 2 // 2 DPs for each server
	}

	surveyID, err := client.SendSurveyCreationQuery(el, servicesunlynxdefault.SurveyID(""), nil, nbrDPs, proofsService, false, sum, count, whereQueryValues, predicate, groupBy)

	if err != nil {
		t.Fatal("Service did not start.", err)
	}

	//save values in a map to verify them at the end
	expectedResults := make(map[[numberGrpAttr]int64][]int64)
	log.Lvl1("Sending response data... ")
	dataHolder := make([]*servicesunlynxdefault.API, 10)
	for i := 0; i < len(dataHolder); i++ {
		dataHolder[i] = servicesunlynxdefault.NewUnLynxClient(el.List[i%5], strconv.Itoa(i+1))
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

		responses := []libunlynx.DpClearResponse{{WhereEnc: sliceWhere, GroupByClear: sliceGrp, AggregatingAttributesEnc: aggr}, {WhereEnc: sliceWhere, GroupByClear: sliceGrp, AggregatingAttributesEnc: aggr}, {WhereEnc: sliceWhere, GroupByClear: sliceGrp1, AggregatingAttributesEnc: aggr}}
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

	if len(tabVerify) == 0 {
		t.Error("Result array should not be empty")
	}
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
	log.Lvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest(libunlynx.SuiTe)
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(5, true)
	defer local.CloseAll()

	// Send a request to the service
	client := servicesunlynxdefault.NewUnLynxClient(el.List[0], strconv.Itoa(0))

	sum := []string{"s1", "s2"}
	count := false
	whereQueryValues := []libunlynx.WhereQueryAttribute{{Name: "w1", Value: *libunlynx.EncryptInt(el.Aggregate, 1)}, {Name: "w2", Value: *libunlynx.EncryptInt(el.Aggregate, 1)}, {Name: "w3", Value: *libunlynx.EncryptInt(el.Aggregate, 1)}} // v1, v3 and v5
	predicate := "(v0 == v1 || v2 == v3) && v4 == v5"
	groupBy := []string{"g1", "g2", "g3"}

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	for _, server := range el.List {
		nbrDPs[server.String()] = 2 // 2 DPs for each server
	}

	surveyID, err := client.SendSurveyCreationQuery(el, servicesunlynxdefault.SurveyID(""), nil, nbrDPs, proofsService, false, sum, count, whereQueryValues, predicate, groupBy)

	if err != nil {
		t.Fatal("Service did not start.", err)
	}

	//save values in a map to verify them at the end
	expectedResults := make(map[[numberGrpAttr]int64][]int64)
	log.Lvl1("Sending response data... ")
	dataHolder := make([]*servicesunlynxdefault.API, 10)
	for i := 0; i < len(dataHolder); i++ {
		dataHolder[i] = servicesunlynxdefault.NewUnLynxClient(el.List[i%5], strconv.Itoa(i+1))
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

		responses := []libunlynx.DpClearResponse{{WhereClear: sliceWhere, GroupByEnc: sliceGrp, AggregatingAttributesEnc: aggr}, {WhereClear: sliceWhere, GroupByEnc: sliceGrp1, AggregatingAttributesEnc: aggr}}
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

	if len(tabVerify) == 0 {
		t.Error("Result array should not be empty")
	}
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
	log.Lvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest(libunlynx.SuiTe)
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(5, true)
	defer local.CloseAll()

	// Send a request to the service
	client := servicesunlynxdefault.NewUnLynxClient(el.List[0], strconv.Itoa(0))

	sum := []string{"s1", "s2"}
	count := false
	whereQueryValues := []libunlynx.WhereQueryAttribute{{Name: "w1", Value: *libunlynx.EncryptInt(el.Aggregate, 1)}, {Name: "w2", Value: *libunlynx.EncryptInt(el.Aggregate, 1)}, {Name: "w3", Value: *libunlynx.EncryptInt(el.Aggregate, 1)}} // v1, v3 and v5
	predicate := "(v0 == v1 || v2 == v3) && v4 == v5"
	groupBy := []string{"g1", "g2", "g3"}

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	for _, server := range el.List {
		nbrDPs[server.String()] = 2 // 2 DPs for each server
	}

	surveyID, err := client.SendSurveyCreationQuery(el, servicesunlynxdefault.SurveyID(""), nil, nbrDPs, proofsService, false, sum, count, whereQueryValues, predicate, groupBy)

	if err != nil {
		t.Fatal("Service did not start.", err)
	}

	//save values in a map to verify them at the end
	expectedResults := make(map[[numberGrpAttr]int64][]int64)
	log.Lvl1("Sending response data... ")
	dataHolder := make([]*servicesunlynxdefault.API, 10)
	for i := 0; i < len(dataHolder); i++ {
		dataHolder[i] = servicesunlynxdefault.NewUnLynxClient(el.List[i%5], strconv.Itoa(i+1))
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

		responses := []libunlynx.DpClearResponse{{WhereEnc: sliceWhere, GroupByEnc: sliceGrp, AggregatingAttributesEnc: aggr}, {WhereEnc: sliceWhere, GroupByEnc: sliceGrp1, AggregatingAttributesEnc: aggr}}
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

	if len(tabVerify) == 0 {
		t.Error("Result array should not be empty")
	}
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
	log.Lvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest(libunlynx.SuiTe)
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(5, true)
	defer local.CloseAll()

	// Send a request to the service
	client := servicesunlynxdefault.NewUnLynxClient(el.List[0], strconv.Itoa(0))

	sum := []string{"s1", "s2"}
	count := false
	whereQueryValues := []libunlynx.WhereQueryAttribute{{Name: "w1", Value: *libunlynx.EncryptInt(el.Aggregate, 1)}, {Name: "w2", Value: *libunlynx.EncryptInt(el.Aggregate, 1)}, {Name: "w3", Value: *libunlynx.EncryptInt(el.Aggregate, 1)}} // v1, v3 and v5
	predicate := "(v0 == v1 || v2 == v3) && v4 == v5"
	groupBy := []string{"g1", "g2", "g3"}

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	for _, server := range el.List {
		nbrDPs[server.String()] = 2 // 2 DPs for each server
	}

	surveyID, err := client.SendSurveyCreationQuery(el, servicesunlynxdefault.SurveyID(""), nil, nbrDPs, proofsService, false, sum, count, whereQueryValues, predicate, groupBy)

	if err != nil {
		t.Fatal("Service did not start.", err)
	}

	//save values in a map to verify them at the end
	expectedResults := make(map[[numberGrpAttr]int64][]int64)
	log.Lvl1("Sending response data... ")
	dataHolder := make([]*servicesunlynxdefault.API, 10)
	for i := 0; i < len(dataHolder); i++ {
		dataHolder[i] = servicesunlynxdefault.NewUnLynxClient(el.List[i%5], strconv.Itoa(i+1))
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

		responses := []libunlynx.DpClearResponse{{WhereClear: sliceWhere, WhereEnc: sliceWhere, GroupByClear: sliceGrp, GroupByEnc: sliceGrp, AggregatingAttributesEnc: aggr}, {WhereClear: sliceWhere, WhereEnc: sliceWhere, GroupByClear: sliceGrp, GroupByEnc: sliceGrp1, AggregatingAttributesEnc: aggr}}
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

	if len(tabVerify) == 0 {
		t.Error("Result array should not be empty")
	}
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
// Only encrypted attributes with count
func TestServiceEncGrpAndWhereAttrWithCount(t *testing.T) {
	log.Lvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest(libunlynx.SuiTe)
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(5, true)
	defer local.CloseAll()

	// Send a request to the service
	client := servicesunlynxdefault.NewUnLynxClient(el.List[0], strconv.Itoa(0))

	sum := []string{"s1", "s2", "count"}
	count := true
	whereQueryValues := []libunlynx.WhereQueryAttribute{{Name: "w1", Value: *libunlynx.EncryptInt(el.Aggregate, 1)}, {Name: "w2", Value: *libunlynx.EncryptInt(el.Aggregate, 1)}, {Name: "w3", Value: *libunlynx.EncryptInt(el.Aggregate, 1)}} // v1, v3 and v5
	predicate := "(v0 == v1 || v2 == v3) && v4 == v5"
	groupBy := []string{"g1", "g2", "g3"}

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	for _, server := range el.List {
		nbrDPs[server.String()] = 2 // 2 DPs for each server
	}

	surveyID, err := client.SendSurveyCreationQuery(el, servicesunlynxdefault.SurveyID(""), nil, nbrDPs, proofsService, false, sum, count, whereQueryValues, predicate, groupBy)

	if err != nil {
		t.Fatal("Service did not start.", err)
	}

	//save values in a map to verify them at the end
	expectedResults := make(map[[numberGrpAttr]int64][]int64)
	log.Lvl1("Sending response data... ")
	dataHolder := make([]*servicesunlynxdefault.API, 10)
	for i := 0; i < len(dataHolder); i++ {
		dataHolder[i] = servicesunlynxdefault.NewUnLynxClient(el.List[i%5], strconv.Itoa(i+1))
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

		responses := []libunlynx.DpClearResponse{{WhereClear: sliceWhere, WhereEnc: sliceWhere, GroupByClear: sliceGrp, GroupByEnc: sliceGrp, AggregatingAttributesEnc: aggr}, {WhereClear: sliceWhere, WhereEnc: sliceWhere, GroupByClear: sliceGrp, GroupByEnc: sliceGrp1, AggregatingAttributesEnc: aggr}}
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

	if len(tabVerify) == 0 {
		t.Error("Result array should not be empty")
	}
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

//______________________________________________________________________________________________________________________
// Servers with no DPs
func TestAllServersNoDPs(t *testing.T) {
	log.Lvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest(libunlynx.SuiTe)
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(5, true)
	defer local.CloseAll()

	// Send a request to the service
	client := servicesunlynxdefault.NewUnLynxClient(el.List[0], strconv.Itoa(0))

	sum := []string{"s1", "s2"}
	count := false
	whereQueryValues := []libunlynx.WhereQueryAttribute{{Name: "w1", Value: *libunlynx.EncryptInt(el.Aggregate, 1)}, {Name: "w2", Value: *libunlynx.EncryptInt(el.Aggregate, 1)}, {Name: "w3", Value: *libunlynx.EncryptInt(el.Aggregate, 1)}} // v1, v3 and v5
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

	surveyID, err := client.SendSurveyCreationQuery(el, servicesunlynxdefault.SurveyID(""), nil, nbrDPs, proofsService, false, sum, count, whereQueryValues, predicate, groupBy)

	if err != nil {
		t.Fatal("Service did not start.")
	}

	//save values in a map to verify them at the end
	expectedResults := make(map[[numberGrpAttr]int64][]int64)
	log.Lvl1("Sending response data... ")
	dataHolder := make([]*servicesunlynxdefault.API, 10)
	for i := 0; i < len(dataHolder); i++ {
		dataHolder[i] = servicesunlynxdefault.NewUnLynxClient(el.List[i%2], strconv.Itoa(i+1))
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

		responses := []libunlynx.DpClearResponse{{WhereClear: sliceWhere, WhereEnc: sliceWhere, GroupByClear: sliceGrp, GroupByEnc: sliceGrp, AggregatingAttributesEnc: aggr}, {WhereClear: sliceWhere, WhereEnc: sliceWhere, GroupByClear: sliceGrp, GroupByEnc: sliceGrp1, AggregatingAttributesEnc: aggr}}
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

	if len(tabVerify) == 0 {
		t.Error("Result array should not be empty")
	}
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
// Servers with a different number of DPs
func TestAllServersRandomDPs(t *testing.T) {
	log.Lvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest(libunlynx.SuiTe)
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(5, true)
	defer local.CloseAll()

	// Send a request to the service
	client := servicesunlynxdefault.NewUnLynxClient(el.List[0], strconv.Itoa(0))

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	nbrDPs[el.List[0].String()] = 0
	nbrDPs[el.List[1].String()] = 2
	nbrDPs[el.List[2].String()] = 1
	nbrDPs[el.List[3].String()] = 3
	nbrDPs[el.List[4].String()] = 4

	sum := []string{"s1", "s2"}
	count := false
	whereQueryValues := []libunlynx.WhereQueryAttribute{{Name: "w1", Value: *libunlynx.EncryptInt(el.Aggregate, 1)}, {Name: "w2", Value: *libunlynx.EncryptInt(el.Aggregate, 1)}, {Name: "w3", Value: *libunlynx.EncryptInt(el.Aggregate, 1)}} // v1, v3 and v5
	predicate := "(v0 == v1 || v2 == v3) && v4 == v5"
	groupBy := []string{"g1", "g2", "g3"}

	surveyID, err := client.SendSurveyCreationQuery(el, servicesunlynxdefault.SurveyID(""), nil, nbrDPs, proofsService, false, sum, count, whereQueryValues, predicate, groupBy)

	if err != nil {
		t.Fatal("Service did not start.")
	}

	//save values in a map to verify them at the end
	expectedResults := make(map[[numberGrpAttr]int64][]int64)
	log.Lvl1("Sending response data... ")
	dataHolder := make([]*servicesunlynxdefault.API, 10)
	for i := 0; i < len(dataHolder); i++ {
		if i < 2 {
			dataHolder[i] = servicesunlynxdefault.NewUnLynxClient(el.List[1], strconv.Itoa(i+1))
		} else if i == 2 {
			dataHolder[i] = servicesunlynxdefault.NewUnLynxClient(el.List[2], strconv.Itoa(i+1))
		} else if i < 6 {
			dataHolder[i] = servicesunlynxdefault.NewUnLynxClient(el.List[3], strconv.Itoa(i+1))
		} else {
			dataHolder[i] = servicesunlynxdefault.NewUnLynxClient(el.List[4], strconv.Itoa(i+1))
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

		responses := []libunlynx.DpClearResponse{{WhereClear: sliceWhere, WhereEnc: sliceWhere, GroupByClear: sliceGrp, GroupByEnc: sliceGrp, AggregatingAttributesEnc: aggr}, {WhereClear: sliceWhere, WhereEnc: sliceWhere, GroupByClear: sliceGrp, GroupByEnc: sliceGrp1, AggregatingAttributesEnc: aggr}}
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

	if len(tabVerify) == 0 {
		t.Error("Result array should not be empty")
	}
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

// TEST BATCH 3 -> Concurrent operations
//______________________________________________________________________________________________________________________

//______________________________________________________________________________________________________________________
// Test multiple requests at the same time
func TestConcurrentSurveys(t *testing.T) {
	log.Lvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest(libunlynx.SuiTe)
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(5, true)
	defer local.CloseAll()

	var wg sync.WaitGroup
	numberThreads := 4

	for i := 0; i < numberThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Send a request to the service
			client := servicesunlynxdefault.NewUnLynxClient(el.List[0], strconv.Itoa(0))

			nbrDPs := make(map[string]int64)
			//how many data providers for each server
			nbrDPs[el.List[0].String()] = 0
			nbrDPs[el.List[1].String()] = 2
			nbrDPs[el.List[2].String()] = 1
			nbrDPs[el.List[3].String()] = 3
			nbrDPs[el.List[4].String()] = 4

			sum := []string{"s1", "s2"}
			count := false
			whereQueryValues := []libunlynx.WhereQueryAttribute{{Name: "w1", Value: *libunlynx.EncryptInt(el.Aggregate, 1)}, {Name: "w2", Value: *libunlynx.EncryptInt(el.Aggregate, 1)}, {Name: "w3", Value: *libunlynx.EncryptInt(el.Aggregate, 1)}} // v1, v3 and v5
			predicate := "(v0 == v1 || v2 == v3) && v4 == v5"
			groupBy := []string{"g1", "g2", "g3"}

			surveyID, err := client.SendSurveyCreationQuery(el, servicesunlynxdefault.SurveyID(""), nil, nbrDPs, proofsService, false, sum, count, whereQueryValues, predicate, groupBy)

			if err != nil {
				t.Fatal("Service did not start.")
			}

			//save values in a map to verify them at the end
			expectedResults := make(map[[numberGrpAttr]int64][]int64)
			log.Lvl1("Sending response data... ")
			dataHolder := make([]*servicesunlynxdefault.API, 10)
			for i := 0; i < len(dataHolder); i++ {
				if i < 2 {
					dataHolder[i] = servicesunlynxdefault.NewUnLynxClient(el.List[1], strconv.Itoa(i+1))
				} else if i == 2 {
					dataHolder[i] = servicesunlynxdefault.NewUnLynxClient(el.List[2], strconv.Itoa(i+1))
				} else if i < 6 {
					dataHolder[i] = servicesunlynxdefault.NewUnLynxClient(el.List[3], strconv.Itoa(i+1))
				} else {
					dataHolder[i] = servicesunlynxdefault.NewUnLynxClient(el.List[4], strconv.Itoa(i+1))
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

				responses := []libunlynx.DpClearResponse{{WhereClear: sliceWhere, WhereEnc: sliceWhere, GroupByClear: sliceGrp, GroupByEnc: sliceGrp, AggregatingAttributesEnc: aggr}, {WhereClear: sliceWhere, WhereEnc: sliceWhere, GroupByClear: sliceGrp, GroupByEnc: sliceGrp1, AggregatingAttributesEnc: aggr}}
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

			if len(tabVerify) == 0 {
				t.Error("Result array should not be empty")
			}
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
		}()
	}
	wg.Wait()
}

func TestFilteringFunc(t *testing.T) {
	predicate := "(v0 == v1 && v2 == v3) && v4 == v5"
	whereQueryValues := []libunlynx.WhereQueryAttributeTagged{{Name: "age", Value: libunlynx.GroupingKey("1")}, {Name: "salary", Value: libunlynx.GroupingKey("1")}, {Name: "joao", Value: libunlynx.GroupingKey("1")}}
	responsesToFilter := []libunlynx.ProcessResponseDet{{DetTagWhere: []libunlynx.GroupingKey{libunlynx.GroupingKey("1"), libunlynx.GroupingKey("1"), libunlynx.GroupingKey("1")}}, {DetTagWhere: []libunlynx.GroupingKey{libunlynx.GroupingKey("1"), libunlynx.GroupingKey("1"), libunlynx.GroupingKey("2")}}}
	log.Lvl1(predicate)
	log.Lvl1(responsesToFilter)
	log.Lvl1(whereQueryValues)
	log.Lvl1(servicesunlynxdefault.FilterResponses(predicate, whereQueryValues, responsesToFilter))
}
