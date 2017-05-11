package serviceI2B2_test

import (
	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/JoaoAndreSa/MedCo/services/i2b2"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"os"
	"strconv"
	"sync"
	"testing"
	"gopkg.in/dedis/crypto.v0/abstract"
)

// TEST BATCH 1 -> normal querying mode
//______________________________________________________________________________________________________________________


func getParam(nbHosts int) (abstract.Scalar, abstract.Point, []string, bool,
	[]lib.WhereQueryAttribute, string, []string, *onet.Roster, *onet.LocalTest,
	[]*serviceI2B2.API, lib.CipherVector) {

	log.LLvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest()
	// generate 3 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(nbHosts, true)

	secKey := network.Suite.Scalar().Pick(random.Stream)
	pubKey := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)

	// Send a request to the service
	clients := make([]*serviceI2B2.API, nbHosts)
	for i := 0 ; i < nbHosts ; i++ {
		clients[i] = serviceI2B2.NewMedcoClient(el.List[i], strconv.Itoa(i))
	}

	// query
	sum := []string{"s1"}
	count := false

	whereQueryValues := make([]lib.WhereQueryAttribute, 0)
	whereQueryValues = append(whereQueryValues, lib.WhereQueryAttribute{Name: "w0", Value: *lib.EncryptInt(el.Aggregate, int64(0))})
	whereQueryValues = append(whereQueryValues, lib.WhereQueryAttribute{Name: "w1", Value: *lib.EncryptInt(el.Aggregate, int64(1))})
	whereQueryValues = append(whereQueryValues, lib.WhereQueryAttribute{Name: "w2", Value: *lib.EncryptInt(el.Aggregate, int64(2))})
	whereQueryValues = append(whereQueryValues, lib.WhereQueryAttribute{Name: "w3", Value: *lib.EncryptInt(el.Aggregate, int64(3))})
	whereQueryValues = append(whereQueryValues, lib.WhereQueryAttribute{Name: "w4", Value: *lib.EncryptInt(el.Aggregate, int64(4))})

	pred := "(exists(v0, r) || exists(v1, r)) && (exists(v2, r) || exists(v3, r)) && exists(v4, r)"
	groupBy := []string{}

	nbrAggr := 1
	aggr := make(lib.CipherVector, nbrAggr)
	for j := 0; j < nbrAggr; j++ {
		aggr[j] = *lib.EncryptInt(el.Aggregate, int64(1))

	}

	return secKey, pubKey, sum, count, whereQueryValues, pred, groupBy, el, local, clients, aggr
}

func getPatients(el *onet.Roster) ([]lib.CipherVector) {
	// data patient 1 = 1
	sliceWhereP1 := make(lib.CipherVector, 0)
	sliceWhereP1 = append(sliceWhereP1, *lib.EncryptInt(el.Aggregate, int64(2)))
	sliceWhereP1 = append(sliceWhereP1, *lib.EncryptInt(el.Aggregate, int64(0)))
	sliceWhereP1 = append(sliceWhereP1, *lib.EncryptInt(el.Aggregate, int64(4)))

	// data patient 2 = 0
	sliceWhereP2 := make(lib.CipherVector, 0)
	sliceWhereP2 = append(sliceWhereP2, *lib.EncryptInt(el.Aggregate, int64(0)))
	sliceWhereP2 = append(sliceWhereP2, *lib.EncryptInt(el.Aggregate, int64(2)))
	sliceWhereP2 = append(sliceWhereP2, *lib.EncryptInt(el.Aggregate, int64(5)))

	// data patient 3 = 1
	sliceWhereP3 := make(lib.CipherVector, 0)
	sliceWhereP3 = append(sliceWhereP3, *lib.EncryptInt(el.Aggregate, int64(0)))
	sliceWhereP3 = append(sliceWhereP3, *lib.EncryptInt(el.Aggregate, int64(2)))
	sliceWhereP3 = append(sliceWhereP3, *lib.EncryptInt(el.Aggregate, int64(4)))
	sliceWhereP3 = append(sliceWhereP3, *lib.EncryptInt(el.Aggregate, int64(1)))
	sliceWhereP3 = append(sliceWhereP3, *lib.EncryptInt(el.Aggregate, int64(1)))
	sliceWhereP3 = append(sliceWhereP3, *lib.EncryptInt(el.Aggregate, int64(1)))
	sliceWhereP3 = append(sliceWhereP3, *lib.EncryptInt(el.Aggregate, int64(1)))
	sliceWhereP3 = append(sliceWhereP3, *lib.EncryptInt(el.Aggregate, int64(1)))

	return []lib.CipherVector{sliceWhereP1, sliceWhereP2, sliceWhereP3}
}

//______________________________________________________________________________________________________________________
// Default (1 data provider per server)
func TestServiceShuffle(t *testing.T) {

	secKey, pubKey, sum, count, whereQueryValues, pred, groupBy, el, local, clients, aggr := getParam(3)
	defer local.CloseAll()

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	for _, server := range el.List {
		nbrDPs[server.String()] = 1 // 1 DPs for each server
	}
	data := []lib.ProcessResponse{}

	patients := getPatients(el)

	data = append(data, lib.ProcessResponse{WhereEnc: patients[0], AggregatingAttributes: aggr})
	data = append(data, lib.ProcessResponse{WhereEnc: patients[1], AggregatingAttributes: aggr})
	data = append(data, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})

	nbrGrp := 3
	sliceGrp := make(lib.CipherVector, nbrGrp)
	for j := 0; j < nbrGrp; j++ {
		sliceGrp[j] = *lib.EncryptInt(el.Aggregate, int64(1))

	}

	wg := lib.StartParallelize(2)

	result1 := lib.FilteredResponse{}
	result2 := lib.FilteredResponse{}
	go func() {
		defer wg.Done()
		data1 := make([]lib.ProcessResponse, len(data))
		copy(data1, data)
		data1 = append(data1, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})
		data1 = append(data1, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})
		data1 = append(data1, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})

		_, result1, _ = clients[1].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data1, 0)
	}()
	go func() {
		defer wg.Done()
		data2 := make([]lib.ProcessResponse, len(data))
		copy(data2, data)

		data2 = append(data, data...)
		data2 = append(data2, data2...)
		_, result2, _ = clients[2].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data2, 0)
	}()
	_, result, err := clients[0].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data, 0)

	if err != nil {
		t.Fatal("Service did not start.", err)
	}

	lib.EndParallelize(wg)

	finalResult := make([]int64, 0)
	expectedResult := []int64{2, 8, 5}

	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result1.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result2.AggregatingAttributes)...)

	assert.Equal(t, len(finalResult), len(expectedResult), "The size of the result is different")

	var check bool
	for _, ev := range expectedResult {
		check = false
		for _, fr := range finalResult {
			if ev == fr {
				check = true
			}
		}

		if !check {
			break
		}
	}

	assert.True(t, check, "Wrong result")

	log.LLvl1(finalResult)
}

//______________________________________________________________________________________________________________________
// Some servers without DPs
func TestServiceNoDPs(t *testing.T) {
	secKey, pubKey, sum, count, whereQueryValues, pred, groupBy, el, local, clients, aggr := getParam(3)
	defer local.CloseAll()

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	nbrDPs[el.List[0].String()] = 1
	nbrDPs[el.List[1].String()] = 1
	nbrDPs[el.List[2].String()] = 0

	data := []lib.ProcessResponse{}

	patients := getPatients(el)

	data = append(data, lib.ProcessResponse{WhereEnc: patients[0], AggregatingAttributes: aggr})
	data = append(data, lib.ProcessResponse{WhereEnc: patients[1], AggregatingAttributes: aggr})
	data = append(data, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})

	nbrGrp := 3
	sliceGrp := make(lib.CipherVector, nbrGrp)
	for j := 0; j < nbrGrp; j++ {
		sliceGrp[j] = *lib.EncryptInt(el.Aggregate, int64(1))

	}

	wg := lib.StartParallelize(1)

	result1 := lib.FilteredResponse{}
	go func() {
		defer wg.Done()
		data1 := make([]lib.ProcessResponse, len(data))
		copy(data1, data)
		data1 = append(data1, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})
		data1 = append(data1, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})
		data1 = append(data1, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})

		_, result1, _ = clients[1].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data1, 0)
	}()
	_, result, err := clients[0].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data, 0)

	if err != nil {
		t.Fatal("Service did not start.", err)
	}

	lib.EndParallelize(wg)

	finalResult := make([]int64, 0)
	expectedResult := []int64{2, 5}

	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result1.AggregatingAttributes)...)

	assert.Equal(t, len(finalResult), len(expectedResult), "The size of the result is different")

	var check bool
	for _, ev := range expectedResult {
		check = false
		for _, fr := range finalResult {
			if ev == fr {
				check = true
			}
		}

		if !check {
			break
		}
	}

	assert.True(t, check, "Wrong result")

	log.LLvl1(finalResult)
}

//______________________________________________________________________________________________________________________
// Servers with a different number of DPs
func TestServiceDifferentDPs(t *testing.T) {
	secKey, pubKey, sum, count, whereQueryValues, pred, groupBy, el, local, _, aggr := getParam(3)
	defer local.CloseAll()

	clients := make([]*serviceI2B2.API, 5)

	// Send a request to the service
	// For the first server
	clients[0] = serviceI2B2.NewMedcoClient(el.List[0], strconv.Itoa(0))
	clients[1] = serviceI2B2.NewMedcoClient(el.List[0], strconv.Itoa(1))

	//For the second server
	clients[2] = serviceI2B2.NewMedcoClient(el.List[1], strconv.Itoa(2))
	clients[3] = serviceI2B2.NewMedcoClient(el.List[1], strconv.Itoa(3))
	clients[4] = serviceI2B2.NewMedcoClient(el.List[1], strconv.Itoa(4))


	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	nbrDPs[el.List[0].String()] = 2
	nbrDPs[el.List[1].String()] = 3
	nbrDPs[el.List[2].String()] = 0

	data := []lib.ProcessResponse{}
	patients := getPatients(el)

	data = append(data, lib.ProcessResponse{WhereEnc: patients[0], AggregatingAttributes: aggr})
	data = append(data, lib.ProcessResponse{WhereEnc: patients[1], AggregatingAttributes: aggr})
	data = append(data, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})

	nbrGrp := 3
	sliceGrp := make(lib.CipherVector, nbrGrp)
	for j := 0; j < nbrGrp; j++ {
		sliceGrp[j] = *lib.EncryptInt(el.Aggregate, int64(1))

	}


	wg := lib.StartParallelize(4)

	result1 := lib.FilteredResponse{}
	result2 := lib.FilteredResponse{}
	result3 := lib.FilteredResponse{}
	result4 := lib.FilteredResponse{}
	go func() {
		defer wg.Done()
		data1 := make([]lib.ProcessResponse, len(data))
		copy(data1, data)
		data1 = append(data1, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})
		data1 = append(data1, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})
		data1 = append(data1, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})
		_, result1, _ = clients[1].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data1, 0)
	}()
	go func() {
		defer wg.Done()
		data2 := make([]lib.ProcessResponse, len(data))
		copy(data2, data)

		data2 = append(data, data...)
		data2 = append(data2, data2...)
		_, result2, _ = clients[2].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data2, 0)
	}()
	go func() {
		defer wg.Done()
		data3 := make([]lib.ProcessResponse, len(data))
		copy(data3, data)

		data3 = append(data, data...)
		data3 = append(data3, data3...)
		_, result3, _ = clients[3].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data3, 0)
	}()
	go func() {
		defer wg.Done()
		data4 := make([]lib.ProcessResponse, len(data))
		copy(data4, data)

		data4 = append(data, data...)
		data4 = append(data4, data4...)
		_, result4, _ = clients[4].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data4, 0)
	}()
	_, result, err := clients[0].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data, 0)

	if err != nil {
		t.Fatal("Service did not start.", err)
	}

	lib.EndParallelize(wg)

	finalResult := make([]int64, 0)
	expectedResult := []int64{2, 5, 8, 8, 8}

	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result1.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result2.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result3.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result4.AggregatingAttributes)...)

	assert.Equal(t, len(finalResult), len(expectedResult), "The size of the result is different")

	var check bool
	for _, ev := range expectedResult {
		check = false
		for _, fr := range finalResult {
			if ev == fr {
				check = true
			}
		}

		if !check {
			break
		}
	}

	assert.True(t, check, "Wrong result")

	log.LLvl1(finalResult)
}

//______________________________________________________________________________________________________________________
// Test a different query and one more node
/* disabled test: no 2 aggregating attributes
func TestServiceDifferentQuery(t *testing.T) {
	secKey, pubKey, _, _, whereQueryValues, _, groupBy, el, local, _, _ := getParam(4)
	defer local.CloseAll()

	clients := make([]*serviceI2B2.API, 6)
	// Send a request to the service
	// For the first server
	clients[0] = serviceI2B2.NewMedcoClient(el.List[0], strconv.Itoa(0))
	clients[1] = serviceI2B2.NewMedcoClient(el.List[0], strconv.Itoa(1))

	//For the second server
	clients[2] = serviceI2B2.NewMedcoClient(el.List[1], strconv.Itoa(2))
	clients[3] = serviceI2B2.NewMedcoClient(el.List[1], strconv.Itoa(3))
	clients[4] = serviceI2B2.NewMedcoClient(el.List[1], strconv.Itoa(4))

	//For the fourth server
	clients[5] = serviceI2B2.NewMedcoClient(el.List[3], strconv.Itoa(4))

	sum := []string{"s1", "s2", "count"}
	count := true
	pred := "(exists(v0, r) || exists(v1, r)) || (exists(v2, r) || exists(v3, r)) || exists(v4, r)"


	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	nbrDPs[el.List[0].String()] = 2
	nbrDPs[el.List[1].String()] = 3
	nbrDPs[el.List[2].String()] = 0
	nbrDPs[el.List[3].String()] = 1

	data := []lib.ProcessResponse{}

	nbrAggr := 2
	aggr := make(lib.CipherVector, nbrAggr)
	for j := 0; j < nbrAggr; j++ {
		aggr[j] = *lib.EncryptInt(el.Aggregate, int64(1))

	}

	if count {
		aggr = append(aggr, *lib.EncryptInt(el.Aggregate, int64(1)))
	}

	patients := getPatients(el)

	data = append(data, lib.ProcessResponse{WhereEnc: patients[0], AggregatingAttributes: aggr})
	data = append(data, lib.ProcessResponse{WhereEnc: patients[1], AggregatingAttributes: aggr})
	data = append(data, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})

	wg := lib.StartParallelize(5)

	result1 := lib.FilteredResponse{}
	result2 := lib.FilteredResponse{}
	result3 := lib.FilteredResponse{}
	result4 := lib.FilteredResponse{}
	result5 := lib.FilteredResponse{}
	go func() {
		defer wg.Done()
		data1 := make([]lib.ProcessResponse, len(data))
		copy(data1, data)
		data1 = append(data1, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})
		data1 = append(data1, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})
		data1 = append(data1, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})
		_, result1, _ = clients[1].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data1, 0)
	}()
	go func() {
		defer wg.Done()
		data2 := make([]lib.ProcessResponse, len(data))
		copy(data2, data)

		data2 = append(data, data...)
		data2 = append(data2, data2...)
		_, result2, _ = clients[2].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data2, 0)
	}()
	go func() {
		defer wg.Done()
		data3 := make([]lib.ProcessResponse, len(data))
		copy(data3, data)

		data3 = append(data, data...)
		data3 = append(data3, data3...)
		_, result3, _ = clients[3].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data3, 0)
	}()
	go func() {
		defer wg.Done()
		data4 := make([]lib.ProcessResponse, len(data))
		copy(data4, data)

		data4 = append(data, data...)
		data4 = append(data4, data4...)
		_, result4, _ = clients[4].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data4, 0)
	}()
	go func() {
		defer wg.Done()
		data5 := make([]lib.ProcessResponse, len(data))
		copy(data5, data)

		data5 = append(data, data...)
		data5 = append(data5, data5...)
		data5 = append(data5, data5...)
		_, result5, _ = clients[5].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data5, 0)
	}()
	_, result, err := clients[0].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data, 0)




	if err != nil {
		t.Fatal("Service did not start.", err)
	}

	lib.EndParallelize(wg)

	finalResult := make([]int64, 0)
	expectedResult := []int64{2, 2, 2, 4, 4, 4, 4, 4, 4, 4, 4, 4, 2, 2, 2, 3, 3, 3}

	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result1.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result2.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result3.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result4.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result5.AggregatingAttributes)...)

	assert.Equal(t, len(finalResult), len(expectedResult), "The size of the result is different")

	var check bool
	for _, ev := range expectedResult {
		check = false
		for _, fr := range finalResult {
			if ev == fr {
				check = true
			}
		}

		if !check {
			break
		}
	}

	assert.True(t, check, "Wrong result")

	log.LLvl1(finalResult)
}
*/

//______________________________________________________________________________________________________________________
// Servers with a different number of DPs
func TestServiceConcurrentSurveys(t *testing.T) {
	secKey, pubKey, sum, count, whereQueryValues, pred, groupBy, el, local, _, aggr := getParam(3)
	defer local.CloseAll()

	var wg sync.WaitGroup
	numberThreads := 4

	// this is only because the surveys all belong to the same machine
	mutex := &sync.Mutex{}
	for i := 0; i < numberThreads; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			clients := make([]*serviceI2B2.API, 5)

			// Send a request to the service
			// For the first server
			clients[0] = serviceI2B2.NewMedcoClient(el.List[0], strconv.Itoa(0))
			clients[1] = serviceI2B2.NewMedcoClient(el.List[0], strconv.Itoa(1))

			//For the second server
			clients[2] = serviceI2B2.NewMedcoClient(el.List[1], strconv.Itoa(2))
			clients[3] = serviceI2B2.NewMedcoClient(el.List[1], strconv.Itoa(3))
			clients[4] = serviceI2B2.NewMedcoClient(el.List[1], strconv.Itoa(4))

			nbrDPs := make(map[string]int64)
			//how many data providers for each server
			nbrDPs[el.List[0].String()] = 2
			nbrDPs[el.List[1].String()] = 3
			nbrDPs[el.List[2].String()] = 0

			data := []lib.ProcessResponse{}

			nbrGrp := 3
			sliceGrp := make(lib.CipherVector, nbrGrp)
			for j := 0; j < nbrGrp; j++ {
				sliceGrp[j] = *lib.EncryptInt(el.Aggregate, int64(1))

			}

			patients := getPatients(el)

			data = append(data, lib.ProcessResponse{WhereEnc: patients[0], AggregatingAttributes: aggr})
			data = append(data, lib.ProcessResponse{WhereEnc: patients[1], AggregatingAttributes: aggr})
			data = append(data, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})

			wg1 := lib.StartParallelize(4)

			result1 := lib.FilteredResponse{}
			result2 := lib.FilteredResponse{}
			result3 := lib.FilteredResponse{}
			result4 := lib.FilteredResponse{}
			go func() {
				defer wg1.Done()
				data1 := make([]lib.ProcessResponse, len(data))
				copy(data1, data)
				data1 = append(data1, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})
				data1 = append(data1, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})
				data1 = append(data1, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})
				_, result1, _ = clients[1].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"+strconv.Itoa(i)), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data1, 0)
			}()
			go func() {
				defer wg1.Done()
				data2 := make([]lib.ProcessResponse, len(data))
				copy(data2, data)

				data2 = append(data, data...)
				data2 = append(data2, data2...)
				_, result2, _ = clients[2].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"+strconv.Itoa(i)), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data2, 0)
			}()
			go func() {
				defer wg1.Done()
				data3 := make([]lib.ProcessResponse, len(data))
				copy(data3, data)

				data3 = append(data, data...)
				data3 = append(data3, data3...)
				_, result3, _ = clients[3].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"+strconv.Itoa(i)), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data3, 0)
			}()
			go func() {
				defer wg1.Done()
				data4 := make([]lib.ProcessResponse, len(data))
				copy(data4, data)

				data4 = append(data, data...)
				data4 = append(data4, data4...)
				data4 = append(data4, data4...)
				_, result4, _ = clients[4].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"+strconv.Itoa(i)), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data4, 0)
			}()
			_, result, err := clients[0].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"+strconv.Itoa(i)), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data, 0)

			if err != nil {
				t.Fatal("Service did not start.", err)
			}

			lib.EndParallelize(wg1)

			finalResult := make([]int64, 0)
			expectedResult := []int64{2, 5, 8, 8, 16}

			mutex.Lock()
			finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result.AggregatingAttributes)...)
			finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result1.AggregatingAttributes)...)
			finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result2.AggregatingAttributes)...)
			finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result3.AggregatingAttributes)...)
			finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result4.AggregatingAttributes)...)
			mutex.Unlock()

			assert.Equal(t, len(finalResult), len(expectedResult), "The size of the result is different")

			var check bool
			for _, ev := range expectedResult {
				check = false
				for _, fr := range finalResult {
					if ev == fr {
						check = true
					}
				}

				if !check {
					break
				}
			}

			assert.True(t, check, "Wrong result")

			log.LLvl1(finalResult)
		}(i)
	}
	wg.Wait()
}

// TEST BATCH 2 -> querying mode 1 (aggregate the final results)
//______________________________________________________________________________________________________________________

//______________________________________________________________________________________________________________________
// Default (1 data provider per server)
func TestServiceAggr(t *testing.T) {

	secKey, pubKey, sum, count, whereQueryValues, pred, groupBy, el, local, clients, aggr := getParam(3)
	defer local.CloseAll()

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	for _, server := range el.List {
		nbrDPs[server.String()] = 1 // 1 DPs for each server
	}
	data := []lib.ProcessResponse{}

	patients := getPatients(el)

	data = append(data, lib.ProcessResponse{WhereEnc: patients[0], AggregatingAttributes: aggr})
	data = append(data, lib.ProcessResponse{WhereEnc: patients[1], AggregatingAttributes: aggr})
	data = append(data, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})

	nbrGrp := 3
	sliceGrp := make(lib.CipherVector, nbrGrp)
	for j := 0; j < nbrGrp; j++ {
		sliceGrp[j] = *lib.EncryptInt(el.Aggregate, int64(1))

	}

	wg := lib.StartParallelize(2)

	result1 := lib.FilteredResponse{}
	result2 := lib.FilteredResponse{}
	go func() {
		defer wg.Done()
		data1 := make([]lib.ProcessResponse, len(data))
		copy(data1, data)
		data1 = append(data1, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})
		data1 = append(data1, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})
		data1 = append(data1, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})

		_, result1, _ = clients[1].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data1, 1)
	}()
	go func() {
		defer wg.Done()
		data2 := make([]lib.ProcessResponse, len(data))
		copy(data2, data)

		data2 = append(data, data...)
		data2 = append(data2, data2...)
		_, result2, _ = clients[2].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data2, 1)
	}()
	_, result, err := clients[0].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data, 1)

	if err != nil {
		t.Fatal("Service did not start.", err)
	}

	lib.EndParallelize(wg)

	finalResult := make([]int64, 0)
	expectedResult := []int64{15, 15, 15}

	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result1.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result2.AggregatingAttributes)...)

	assert.Equal(t, len(finalResult), len(expectedResult), "The size of the result is different")

	var check bool
	for _, ev := range expectedResult {
		check = false
		for _, fr := range finalResult {
			if ev == fr {
				check = true
			}
		}

		if !check {
			break
		}
	}

	assert.True(t, check, "Wrong result")

	log.LLvl1(finalResult)
}

//______________________________________________________________________________________________________________________
// Some servers without DPs
func TestServiceNoDPsAggr(t *testing.T) {
	secKey, pubKey, sum, count, whereQueryValues, pred, groupBy, el, local, clients, aggr := getParam(3)
	defer local.CloseAll()

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	nbrDPs[el.List[0].String()] = 1
	nbrDPs[el.List[1].String()] = 1
	nbrDPs[el.List[2].String()] = 0

	data := []lib.ProcessResponse{}

	patients := getPatients(el)

	data = append(data, lib.ProcessResponse{WhereEnc: patients[0], AggregatingAttributes: aggr})
	data = append(data, lib.ProcessResponse{WhereEnc: patients[1], AggregatingAttributes: aggr})
	data = append(data, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})

	nbrGrp := 3
	sliceGrp := make(lib.CipherVector, nbrGrp)
	for j := 0; j < nbrGrp; j++ {
		sliceGrp[j] = *lib.EncryptInt(el.Aggregate, int64(1))

	}

	wg := lib.StartParallelize(1)

	result1 := lib.FilteredResponse{}
	go func() {
		defer wg.Done()
		data1 := make([]lib.ProcessResponse, len(data))
		copy(data1, data)
		data1 = append(data1, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})
		data1 = append(data1, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})
		data1 = append(data1, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})

		_, result1, _ = clients[1].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data1, 1)
	}()
	_, result, err := clients[0].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data, 1)

	if err != nil {
		t.Fatal("Service did not start.", err)
	}

	lib.EndParallelize(wg)

	finalResult := make([]int64, 0)
	expectedResult := []int64{7, 7}

	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result1.AggregatingAttributes)...)

	assert.Equal(t, len(finalResult), len(expectedResult), "The size of the result is different")

	var check bool
	for _, ev := range expectedResult {
		check = false
		for _, fr := range finalResult {
			if ev == fr {
				check = true
			}
		}

		if !check {
			break
		}
	}

	assert.True(t, check, "Wrong result")

	log.LLvl1(finalResult)
}

//______________________________________________________________________________________________________________________
// Servers with a different number of DPs
func TestServiceDifferentDPsAggr(t *testing.T) {
	secKey, pubKey, sum, count, whereQueryValues, pred, groupBy, el, local, _, aggr := getParam(3)
	defer local.CloseAll()

	clients := make([]*serviceI2B2.API, 5)

	// Send a request to the service
	// For the first server
	clients[0] = serviceI2B2.NewMedcoClient(el.List[0], strconv.Itoa(0))
	clients[1] = serviceI2B2.NewMedcoClient(el.List[0], strconv.Itoa(1))

	//For the second server
	clients[2] = serviceI2B2.NewMedcoClient(el.List[1], strconv.Itoa(2))
	clients[3] = serviceI2B2.NewMedcoClient(el.List[1], strconv.Itoa(3))
	clients[4] = serviceI2B2.NewMedcoClient(el.List[1], strconv.Itoa(4))


	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	nbrDPs[el.List[0].String()] = 2
	nbrDPs[el.List[1].String()] = 3
	nbrDPs[el.List[2].String()] = 0

	data := []lib.ProcessResponse{}
	patients := getPatients(el)

	data = append(data, lib.ProcessResponse{WhereEnc: patients[0], AggregatingAttributes: aggr})
	data = append(data, lib.ProcessResponse{WhereEnc: patients[1], AggregatingAttributes: aggr})
	data = append(data, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})

	nbrGrp := 3
	sliceGrp := make(lib.CipherVector, nbrGrp)
	for j := 0; j < nbrGrp; j++ {
		sliceGrp[j] = *lib.EncryptInt(el.Aggregate, int64(1))

	}


	wg := lib.StartParallelize(4)

	result1 := lib.FilteredResponse{}
	result2 := lib.FilteredResponse{}
	result3 := lib.FilteredResponse{}
	result4 := lib.FilteredResponse{}
	go func() {
		defer wg.Done()
		data1 := make([]lib.ProcessResponse, len(data))
		copy(data1, data)
		data1 = append(data1, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})
		data1 = append(data1, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})
		data1 = append(data1, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})
		_, result1, _ = clients[1].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data1, 1)
	}()
	go func() {
		defer wg.Done()
		data2 := make([]lib.ProcessResponse, len(data))
		copy(data2, data)

		data2 = append(data, data...)
		data2 = append(data2, data2...)
		_, result2, _ = clients[2].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data2, 1)
	}()
	go func() {
		defer wg.Done()
		data3 := make([]lib.ProcessResponse, len(data))
		copy(data3, data)

		data3 = append(data, data...)
		data3 = append(data3, data3...)
		_, result3, _ = clients[3].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data3, 1)
	}()
	go func() {
		defer wg.Done()
		data4 := make([]lib.ProcessResponse, len(data))
		copy(data4, data)

		data4 = append(data, data...)
		data4 = append(data4, data4...)
		_, result4, _ = clients[4].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data4, 1)
	}()
	_, result, err := clients[0].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data, 1)

	if err != nil {
		t.Fatal("Service did not start.", err)
	}

	lib.EndParallelize(wg)

	finalResult := make([]int64, 0)
	expectedResult := []int64{31, 31, 31, 31, 31}

	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result1.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result2.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result3.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result4.AggregatingAttributes)...)

	assert.Equal(t, len(finalResult), len(expectedResult), "The size of the result is different")

	var check bool
	for _, ev := range expectedResult {
		check = false
		for _, fr := range finalResult {
			if ev == fr {
				check = true
			}
		}

		if !check {
			break
		}
	}

	assert.True(t, check, "Wrong result")

	log.LLvl1(finalResult)
}


//______________________________________________________________________________________________________________________
// Test a different query and one more node
/* disabled test: no 2 aggregating attributes
func TestServiceDifferentQueryAggr(t *testing.T) {
	log.LLvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest()
	// generate 4 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(4, true)
	defer local.CloseAll()

	secKey := network.Suite.Scalar().Pick(random.Stream)
	pubKey := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)
	// Send a request to the service
	// For the first server
	client := serviceI2B2.NewMedcoClient(el.List[0], strconv.Itoa(0))
	client1 := serviceI2B2.NewMedcoClient(el.List[0], strconv.Itoa(1))

	//For the second server
	client2 := serviceI2B2.NewMedcoClient(el.List[1], strconv.Itoa(2))
	client3 := serviceI2B2.NewMedcoClient(el.List[1], strconv.Itoa(3))
	client4 := serviceI2B2.NewMedcoClient(el.List[1], strconv.Itoa(4))

	//For the fourth server
	client5 := serviceI2B2.NewMedcoClient(el.List[3], strconv.Itoa(4))

	sum := []string{"s1", "s2", "count"}
	count := true
	whereQueryValues := []lib.WhereQueryAttribute{{Name: "w1", Value: *lib.EncryptInt(el.Aggregate, 1)}} // v1
	pred := "v0 == v1"
	groupBy := []string{}

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	nbrDPs[el.List[0].String()] = 2
	nbrDPs[el.List[1].String()] = 3
	nbrDPs[el.List[2].String()] = 0
	nbrDPs[el.List[3].String()] = 1

	data := []lib.ProcessResponse{}
	val := int64(1)

	nbrWhere := 1
	sliceWhere := make(lib.CipherVector, nbrWhere)
	for j := 0; j < nbrWhere; j++ {
		sliceWhere[j] = *lib.EncryptInt(el.Aggregate, val)

	}

	sliceWhere1 := make(lib.CipherVector, nbrWhere)
	for j := 0; j < nbrWhere; j++ {
		sliceWhere1[j] = *lib.EncryptInt(el.Aggregate, 0)

	}

	nbrAggr := 2
	aggr := make(lib.CipherVector, nbrAggr)
	for j := 0; j < nbrAggr; j++ {
		aggr[j] = *lib.EncryptInt(el.Aggregate, val)

	}

	if count {
		aggr = append(aggr, *lib.EncryptInt(el.Aggregate, val))
	}

	data = append(data, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr}, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr}, lib.ProcessResponse{WhereEnc: sliceWhere1, AggregatingAttributes: aggr})

	wg := lib.StartParallelize(5)

	result1 := lib.FilteredResponse{}
	result2 := lib.FilteredResponse{}
	result3 := lib.FilteredResponse{}
	result4 := lib.FilteredResponse{}
	result5 := lib.FilteredResponse{}
	go func() {
		defer wg.Done()
		data1 := append(data, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr})
		_, result1, _ = client1.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data1, 1)
	}()
	go func() {
		defer wg.Done()
		data2 := append(data, data...)
		_, result2, _ = client2.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data2, 1)
	}()
	go func() {
		defer wg.Done()
		data3 := append(data, data...)
		_, result3, _ = client3.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data3, 1)
	}()
	go func() {
		defer wg.Done()
		data4 := append(data, data...)
		_, result4, _ = client4.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data4, 1)
	}()
	go func() {
		defer wg.Done()
		data5 := append(data, lib.ProcessResponse{WhereEnc: sliceWhere1, AggregatingAttributes: aggr})
		_, result5, _ = client5.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data5, 1)
	}()
	_, result, err := client.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data, 1)

	if err != nil {
		t.Fatal("Service did not start.", err)
	}

	lib.EndParallelize(wg)

	finalResult := make([]int64, 0)
	expectedResult := []int64{19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19}

	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result1.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result2.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result3.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result4.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result5.AggregatingAttributes)...)

	assert.Equal(t, len(finalResult), len(expectedResult), "The size of the result is different")
	assert.Equal(t, finalResult, expectedResult, "Wrong result")

	log.LLvl1(finalResult)
}
*/

//______________________________________________________________________________________________________________________
// Servers with a different number of DPs
func TestServiceConcurrentSurveysAggr(t *testing.T) {
	secKey, pubKey, sum, count, whereQueryValues, pred, groupBy, el, local, _, aggr := getParam(3)
	defer local.CloseAll()

	var wg sync.WaitGroup
	numberThreads := 4

	// this is only because the surveys all belong to the same machine
	mutex := &sync.Mutex{}
	for i := 0; i < numberThreads; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			clients := make([]*serviceI2B2.API, 5)

			// Send a request to the service
			// For the first server
			clients[0] = serviceI2B2.NewMedcoClient(el.List[0], strconv.Itoa(0))
			clients[1] = serviceI2B2.NewMedcoClient(el.List[0], strconv.Itoa(1))

			//For the second server
			clients[2] = serviceI2B2.NewMedcoClient(el.List[1], strconv.Itoa(2))
			clients[3] = serviceI2B2.NewMedcoClient(el.List[1], strconv.Itoa(3))
			clients[4] = serviceI2B2.NewMedcoClient(el.List[1], strconv.Itoa(4))

			nbrDPs := make(map[string]int64)
			//how many data providers for each server
			nbrDPs[el.List[0].String()] = 2
			nbrDPs[el.List[1].String()] = 3
			nbrDPs[el.List[2].String()] = 0

			data := []lib.ProcessResponse{}

			nbrGrp := 3
			sliceGrp := make(lib.CipherVector, nbrGrp)
			for j := 0; j < nbrGrp; j++ {
				sliceGrp[j] = *lib.EncryptInt(el.Aggregate, int64(1))

			}

			patients := getPatients(el)

			data = append(data, lib.ProcessResponse{WhereEnc: patients[0], AggregatingAttributes: aggr})
			data = append(data, lib.ProcessResponse{WhereEnc: patients[1], AggregatingAttributes: aggr})
			data = append(data, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})

			wg1 := lib.StartParallelize(4)

			result1 := lib.FilteredResponse{}
			result2 := lib.FilteredResponse{}
			result3 := lib.FilteredResponse{}
			result4 := lib.FilteredResponse{}
			go func() {
				defer wg1.Done()
				data1 := make([]lib.ProcessResponse, len(data))
				copy(data1, data)
				data1 = append(data1, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})
				data1 = append(data1, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})
				data1 = append(data1, lib.ProcessResponse{WhereEnc: patients[2], AggregatingAttributes: aggr})
				_, result1, _ = clients[1].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"+strconv.Itoa(i)), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data1, 1)
			}()
			go func() {
				defer wg1.Done()
				data2 := make([]lib.ProcessResponse, len(data))
				copy(data2, data)

				data2 = append(data, data...)
				data2 = append(data2, data2...)
				_, result2, _ = clients[2].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"+strconv.Itoa(i)), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data2, 1)
			}()
			go func() {
				defer wg1.Done()
				data3 := make([]lib.ProcessResponse, len(data))
				copy(data3, data)

				data3 = append(data, data...)
				data3 = append(data3, data3...)
				_, result3, _ = clients[3].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"+strconv.Itoa(i)), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data3, 1)
			}()
			go func() {
				defer wg1.Done()
				data4 := make([]lib.ProcessResponse, len(data))
				copy(data4, data)

				data4 = append(data, data...)
				data4 = append(data4, data4...)
				data4 = append(data4, data4...)
				_, result4, _ = clients[4].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"+strconv.Itoa(i)), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data4, 1)
			}()
			_, result, err := clients[0].SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"+strconv.Itoa(i)), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data, 1)

			if err != nil {
				t.Fatal("Service did not start.", err)
			}

			lib.EndParallelize(wg1)

			finalResult := make([]int64, 0)
			expectedResult := []int64{39, 39, 39, 39, 39}

			mutex.Lock()
			finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result.AggregatingAttributes)...)
			finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result1.AggregatingAttributes)...)
			finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result2.AggregatingAttributes)...)
			finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result3.AggregatingAttributes)...)
			finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result4.AggregatingAttributes)...)
			mutex.Unlock()

			assert.Equal(t, len(finalResult), len(expectedResult), "The size of the result is different")

			var check bool
			for _, ev := range expectedResult {
				check = false
				for _, fr := range finalResult {
					if ev == fr {
						check = true
					}
				}

				if !check {
					break
				}
			}

			assert.True(t, check, "Wrong result")

			log.LLvl1(finalResult)
		}(i)
	}
	wg.Wait()
}

