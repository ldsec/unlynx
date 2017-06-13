package serviceI2B2_test

import (
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/services/i2b2"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"os"
	"strconv"
	"sync"
	"testing"
)

// TEST BATCH 1 -> normal querying mode
//______________________________________________________________________________________________________________________

//______________________________________________________________________________________________________________________
// Default (1 data provider per server)
func TestServiceShuffle(t *testing.T) {
	log.Lvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest()
	// generate 3 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(3, true)
	defer local.CloseAll()

	secKey := network.Suite.Scalar().Pick(random.Stream)
	pubKey := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)
	// Send a request to the service
	client := serviceI2B2.NewUnLynxClient(el.List[0], strconv.Itoa(0))
	client1 := serviceI2B2.NewUnLynxClient(el.List[1], strconv.Itoa(1))
	client2 := serviceI2B2.NewUnLynxClient(el.List[2], strconv.Itoa(2))

	sum := []string{"s1"}
	count := false
	whereQueryValues := []lib.WhereQueryAttribute{{Name: "w1", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w2", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w3", Value: *lib.EncryptInt(el.Aggregate, 1)}} // v1, v3 and v5
	pred := "(v0 == v1 || v2 == v3) && v4 == v5"
	groupBy := []string{}

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	for _, server := range el.List {
		nbrDPs[server.String()] = 1 // 1 DPs for each server
	}
	data := []lib.ProcessResponse{}
	val := int64(1)

	nbrWhere := 3
	sliceWhere := make(lib.CipherVector, nbrWhere)
	for j := 0; j < nbrWhere; j++ {
		sliceWhere[j] = *lib.EncryptInt(el.Aggregate, val)

	}

	sliceWhere1 := make(lib.CipherVector, nbrWhere)
	for j := 0; j < nbrWhere; j++ {
		sliceWhere1[j] = *lib.EncryptInt(el.Aggregate, val)

	}

	nbrGrp := 3
	sliceGrp := make(lib.CipherVector, nbrGrp)
	for j := 0; j < nbrGrp; j++ {
		sliceGrp[j] = *lib.EncryptInt(el.Aggregate, val)

	}

	nbrAggr := 1
	aggr := make(lib.CipherVector, nbrAggr)
	for j := 0; j < nbrAggr; j++ {
		aggr[j] = *lib.EncryptInt(el.Aggregate, val)

	}

	data = append(data, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr}, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr}, lib.ProcessResponse{WhereEnc: sliceWhere1, AggregatingAttributes: aggr})

	wg := lib.StartParallelize(2)

	result1 := lib.FilteredResponse{}
	result2 := lib.FilteredResponse{}
	go func() {
		defer wg.Done()
		data1 := append(data, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr})
		_, result1, _ = client1.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data1, 0)
	}()
	go func() {
		defer wg.Done()
		data2 := append(data, data...)
		_, result2, _ = client2.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data2, 0)
	}()
	_, result, err := client.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data, 0)

	if err != nil {
		t.Fatal("Service did not start.", err)
	}

	lib.EndParallelize(wg)

	finalResult := make([]int64, 0)
	expectedResult := []int64{3, 4, 6}

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

	log.Lvl1(finalResult)
}

//______________________________________________________________________________________________________________________
// Some servers without DPs
func TestServiceNoDPs(t *testing.T) {
	log.Lvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest()
	// generate 3 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(3, true)
	defer local.CloseAll()

	secKey := network.Suite.Scalar().Pick(random.Stream)
	pubKey := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)
	// Send a request to the service
	client := serviceI2B2.NewUnLynxClient(el.List[0], strconv.Itoa(0))
	client1 := serviceI2B2.NewUnLynxClient(el.List[1], strconv.Itoa(1))

	sum := []string{"s1"}
	count := false
	whereQueryValues := []lib.WhereQueryAttribute{{Name: "w1", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w2", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w3", Value: *lib.EncryptInt(el.Aggregate, 1)}} // v1, v3 and v5
	pred := "(v0 == v1 || v2 == v3) && v4 == v5"
	groupBy := []string{}

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	nbrDPs[el.List[0].String()] = 1
	nbrDPs[el.List[1].String()] = 1
	nbrDPs[el.List[2].String()] = 0

	data := []lib.ProcessResponse{}
	val := int64(1)

	nbrWhere := 3
	sliceWhere := make(lib.CipherVector, nbrWhere)
	for j := 0; j < nbrWhere; j++ {
		sliceWhere[j] = *lib.EncryptInt(el.Aggregate, val)

	}

	sliceWhere1 := make(lib.CipherVector, nbrWhere)
	for j := 0; j < nbrWhere; j++ {
		sliceWhere1[j] = *lib.EncryptInt(el.Aggregate, val)

	}

	nbrGrp := 3
	sliceGrp := make(lib.CipherVector, nbrGrp)
	for j := 0; j < nbrGrp; j++ {
		sliceGrp[j] = *lib.EncryptInt(el.Aggregate, val)

	}

	nbrAggr := 1
	aggr := make(lib.CipherVector, nbrAggr)
	for j := 0; j < nbrAggr; j++ {
		aggr[j] = *lib.EncryptInt(el.Aggregate, val)

	}

	data = append(data, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr}, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr}, lib.ProcessResponse{WhereEnc: sliceWhere1, AggregatingAttributes: aggr})

	wg := lib.StartParallelize(1)

	result1 := lib.FilteredResponse{}
	go func() {
		defer wg.Done()
		data1 := append(data, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr})
		_, result1, _ = client1.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data1, 0)
	}()
	_, result, err := client.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data, 0)

	if err != nil {
		t.Fatal("Service did not start.", err)
	}

	lib.EndParallelize(wg)

	finalResult := make([]int64, 0)
	expectedResult := []int64{3, 4}

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

	log.Lvl1(finalResult)
}

//______________________________________________________________________________________________________________________
// Servers with a different number of DPs
func TestServiceDifferentDPs(t *testing.T) {
	log.Lvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest()
	// generate 3 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(3, true)
	defer local.CloseAll()

	secKey := network.Suite.Scalar().Pick(random.Stream)
	pubKey := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)
	// Send a request to the service
	// For the first server
	client := serviceI2B2.NewUnLynxClient(el.List[0], strconv.Itoa(0))
	client1 := serviceI2B2.NewUnLynxClient(el.List[0], strconv.Itoa(1))

	//For the second server
	client2 := serviceI2B2.NewUnLynxClient(el.List[1], strconv.Itoa(2))
	client3 := serviceI2B2.NewUnLynxClient(el.List[1], strconv.Itoa(3))
	client4 := serviceI2B2.NewUnLynxClient(el.List[1], strconv.Itoa(4))

	sum := []string{"s1"}
	count := false
	whereQueryValues := []lib.WhereQueryAttribute{{Name: "w1", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w2", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w3", Value: *lib.EncryptInt(el.Aggregate, 1)}} // v1, v3 and v5
	pred := "(v0 == v1 || v2 == v3) && v4 == v5"
	groupBy := []string{}

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	nbrDPs[el.List[0].String()] = 2
	nbrDPs[el.List[1].String()] = 3
	nbrDPs[el.List[2].String()] = 0

	data := []lib.ProcessResponse{}
	val := int64(1)

	nbrWhere := 3
	sliceWhere := make(lib.CipherVector, nbrWhere)
	for j := 0; j < nbrWhere; j++ {
		sliceWhere[j] = *lib.EncryptInt(el.Aggregate, val)

	}

	sliceWhere1 := make(lib.CipherVector, nbrWhere)
	for j := 0; j < nbrWhere; j++ {
		sliceWhere1[j] = *lib.EncryptInt(el.Aggregate, val)

	}

	nbrGrp := 3
	sliceGrp := make(lib.CipherVector, nbrGrp)
	for j := 0; j < nbrGrp; j++ {
		sliceGrp[j] = *lib.EncryptInt(el.Aggregate, val)

	}

	nbrAggr := 1
	aggr := make(lib.CipherVector, nbrAggr)
	for j := 0; j < nbrAggr; j++ {
		aggr[j] = *lib.EncryptInt(el.Aggregate, val)

	}

	data = append(data, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr}, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr}, lib.ProcessResponse{WhereEnc: sliceWhere1, AggregatingAttributes: aggr})

	wg := lib.StartParallelize(4)

	result1 := lib.FilteredResponse{}
	result2 := lib.FilteredResponse{}
	result3 := lib.FilteredResponse{}
	result4 := lib.FilteredResponse{}
	go func() {
		defer wg.Done()
		data1 := append(data, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr})
		_, result1, _ = client1.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data1, 0)
	}()
	go func() {
		defer wg.Done()
		data2 := append(data, data...)
		_, result2, _ = client2.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data2, 0)
	}()
	go func() {
		defer wg.Done()
		data3 := append(data, data...)
		_, result3, _ = client3.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data3, 0)
	}()
	go func() {
		defer wg.Done()
		data4 := append(data, data...)
		_, result4, _ = client4.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data4, 0)
	}()
	_, result, err := client.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data, 0)

	if err != nil {
		t.Fatal("Service did not start.", err)
	}

	lib.EndParallelize(wg)

	finalResult := make([]int64, 0)
	expectedResult := []int64{3, 4, 6, 6, 6}

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

	log.Lvl1(finalResult)
}

//______________________________________________________________________________________________________________________
// Test a different query and one more node
func TestServiceDifferentQuery(t *testing.T) {
	log.Lvl1("***************************************************************************************************")
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
	client := serviceI2B2.NewUnLynxClient(el.List[0], strconv.Itoa(0))
	client1 := serviceI2B2.NewUnLynxClient(el.List[0], strconv.Itoa(1))

	//For the second server
	client2 := serviceI2B2.NewUnLynxClient(el.List[1], strconv.Itoa(2))
	client3 := serviceI2B2.NewUnLynxClient(el.List[1], strconv.Itoa(3))
	client4 := serviceI2B2.NewUnLynxClient(el.List[1], strconv.Itoa(4))

	//For the fourth server
	client5 := serviceI2B2.NewUnLynxClient(el.List[3], strconv.Itoa(4))

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
		_, result1, _ = client1.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data1, 0)
	}()
	go func() {
		defer wg.Done()
		data2 := append(data, data...)
		_, result2, _ = client2.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data2, 0)
	}()
	go func() {
		defer wg.Done()
		data3 := append(data, data...)
		_, result3, _ = client3.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data3, 0)
	}()
	go func() {
		defer wg.Done()
		data4 := append(data, data...)
		_, result4, _ = client4.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data4, 0)
	}()
	go func() {
		defer wg.Done()
		data5 := append(data, lib.ProcessResponse{WhereEnc: sliceWhere1, AggregatingAttributes: aggr})
		_, result5, _ = client5.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data5, 0)
	}()
	_, result, err := client.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data, 0)

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

	log.Lvl1(finalResult)
}

//______________________________________________________________________________________________________________________
// Servers with a different number of DPs
func TestServiceConcurrentSurveys(t *testing.T) {
	log.Lvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest()
	// generate 3 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(3, true)
	defer local.CloseAll()

	var wg sync.WaitGroup
	numberThreads := 4

	// this is only because the surveys all belong to the same machine
	mutex := &sync.Mutex{}
	for i := 0; i < numberThreads; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			secKey := network.Suite.Scalar().Pick(random.Stream)
			pubKey := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)
			// Send a request to the service
			// For the first server
			client := serviceI2B2.NewUnLynxClient(el.List[0], strconv.Itoa(0))
			client1 := serviceI2B2.NewUnLynxClient(el.List[0], strconv.Itoa(1))

			//For the second server
			client2 := serviceI2B2.NewUnLynxClient(el.List[1], strconv.Itoa(2))
			client3 := serviceI2B2.NewUnLynxClient(el.List[1], strconv.Itoa(3))
			client4 := serviceI2B2.NewUnLynxClient(el.List[1], strconv.Itoa(4))

			sum := []string{"s1"}
			count := false
			whereQueryValues := []lib.WhereQueryAttribute{{Name: "w1", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w2", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w3", Value: *lib.EncryptInt(el.Aggregate, 1)}} // v1, v3 and v5
			pred := "(v0 == v1 || v2 == v3) && v4 == v5"
			groupBy := []string{}

			nbrDPs := make(map[string]int64)
			//how many data providers for each server
			nbrDPs[el.List[0].String()] = 2
			nbrDPs[el.List[1].String()] = 3
			nbrDPs[el.List[2].String()] = 0

			data := []lib.ProcessResponse{}
			val := int64(1)

			nbrWhere := 3
			sliceWhere := make(lib.CipherVector, nbrWhere)
			for j := 0; j < nbrWhere; j++ {
				sliceWhere[j] = *lib.EncryptInt(el.Aggregate, val)

			}

			sliceWhere1 := make(lib.CipherVector, nbrWhere)
			for j := 0; j < nbrWhere; j++ {
				sliceWhere1[j] = *lib.EncryptInt(el.Aggregate, val)

			}

			nbrGrp := 3
			sliceGrp := make(lib.CipherVector, nbrGrp)
			for j := 0; j < nbrGrp; j++ {
				sliceGrp[j] = *lib.EncryptInt(el.Aggregate, val)

			}

			nbrAggr := 1
			aggr := make(lib.CipherVector, nbrAggr)
			for j := 0; j < nbrAggr; j++ {
				aggr[j] = *lib.EncryptInt(el.Aggregate, val)

			}

			data = append(data, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr}, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr}, lib.ProcessResponse{WhereEnc: sliceWhere1, AggregatingAttributes: aggr})

			wg1 := lib.StartParallelize(4)

			result1 := lib.FilteredResponse{}
			result2 := lib.FilteredResponse{}
			result3 := lib.FilteredResponse{}
			result4 := lib.FilteredResponse{}
			go func() {
				defer wg1.Done()
				data1 := append(data, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr})
				_, result1, _ = client1.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"+strconv.Itoa(i)), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data1, 0)
			}()
			go func() {
				defer wg1.Done()
				data2 := append(data, data...)
				_, result2, _ = client2.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"+strconv.Itoa(i)), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data2, 0)
			}()
			go func() {
				defer wg1.Done()
				data3 := append(data, data...)
				_, result3, _ = client3.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"+strconv.Itoa(i)), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data3, 0)
			}()
			go func() {
				defer wg1.Done()
				data4 := append(data, data...)
				_, result4, _ = client4.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"+strconv.Itoa(i)), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data4, 0)
			}()
			_, result, err := client.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"+strconv.Itoa(i)), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data, 0)

			if err != nil {
				t.Fatal("Service did not start.", err)
			}

			lib.EndParallelize(wg1)

			finalResult := make([]int64, 0)
			expectedResult := []int64{3, 4, 6, 6, 6}

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

			log.Lvl1(finalResult)
		}(i)
	}
	wg.Wait()
}

// TEST BATCH 2 -> querying mode 1 (aggregate the final results)
//______________________________________________________________________________________________________________________

//______________________________________________________________________________________________________________________
// Default (1 data provider per server)
func TestServiceAggr(t *testing.T) {
	log.Lvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest()
	// generate 3 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(3, true)
	defer local.CloseAll()

	secKey := network.Suite.Scalar().Pick(random.Stream)
	pubKey := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)
	// Send a request to the service
	client := serviceI2B2.NewUnLynxClient(el.List[0], strconv.Itoa(0))
	client1 := serviceI2B2.NewUnLynxClient(el.List[1], strconv.Itoa(1))
	client2 := serviceI2B2.NewUnLynxClient(el.List[2], strconv.Itoa(2))

	sum := []string{"sum1"}
	count := false
	whereQueryValues := []lib.WhereQueryAttribute{{Name: "w1", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w2", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w3", Value: *lib.EncryptInt(el.Aggregate, 1)}} // v1, v3 and v5
	pred := "(v0 == v1 || v2 == v3) && v4 == v5"
	groupBy := []string{}

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	for _, server := range el.List {
		nbrDPs[server.String()] = 1 // 1 DPs for each server
	}
	data := []lib.ProcessResponse{}
	val := int64(1)

	nbrWhere := 3
	sliceWhere := make(lib.CipherVector, nbrWhere)
	for j := 0; j < nbrWhere; j++ {
		sliceWhere[j] = *lib.EncryptInt(el.Aggregate, val)

	}

	sliceWhere1 := make(lib.CipherVector, nbrWhere)
	for j := 0; j < nbrWhere; j++ {
		sliceWhere1[j] = *lib.EncryptInt(el.Aggregate, val)

	}

	nbrGrp := 3
	sliceGrp := make(lib.CipherVector, nbrGrp)
	for j := 0; j < nbrGrp; j++ {
		sliceGrp[j] = *lib.EncryptInt(el.Aggregate, val)

	}

	nbrAggr := 1
	aggr := make(lib.CipherVector, nbrAggr)
	for j := 0; j < nbrAggr; j++ {
		aggr[j] = *lib.EncryptInt(el.Aggregate, val)

	}

	data = append(data, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr}, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr}, lib.ProcessResponse{WhereEnc: sliceWhere1, AggregatingAttributes: aggr})

	wg := lib.StartParallelize(2)

	result1 := lib.FilteredResponse{}
	result2 := lib.FilteredResponse{}
	go func() {
		defer wg.Done()
		data1 := append(data, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr})
		_, result1, _ = client1.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true /*this permits to use precomputation for shuffling*/, sum, count, whereQueryValues, pred, groupBy, data1, 1)
	}()
	go func() {
		defer wg.Done()
		data2 := append(data, data...)
		_, result2, _ = client2.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data2, 1)
	}()
	_, result, err := client.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data, 1)

	if err != nil {
		t.Fatal("Service did not start.", err)
	}

	lib.EndParallelize(wg)

	finalResult := make([]int64, 0)
	expectedResult := []int64{13, 13, 13}

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

	log.Lvl1(finalResult)
}

//______________________________________________________________________________________________________________________
// Some servers without DPs
func TestServiceNoDPsAggr(t *testing.T) {
	log.Lvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest()
	// generate 3 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(3, true)
	defer local.CloseAll()

	secKey := network.Suite.Scalar().Pick(random.Stream)
	pubKey := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)
	// Send a request to the service
	client := serviceI2B2.NewUnLynxClient(el.List[0], strconv.Itoa(0))
	client1 := serviceI2B2.NewUnLynxClient(el.List[1], strconv.Itoa(1))

	sum := []string{"s1"}
	count := false
	whereQueryValues := []lib.WhereQueryAttribute{{Name: "w1", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w2", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w3", Value: *lib.EncryptInt(el.Aggregate, 1)}} // v1, v3 and v5
	pred := "(v0 == v1 || v2 == v3) && v4 == v5"
	groupBy := []string{}

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	nbrDPs[el.List[0].String()] = 1
	nbrDPs[el.List[1].String()] = 1
	nbrDPs[el.List[2].String()] = 0

	data := []lib.ProcessResponse{}
	val := int64(1)

	nbrWhere := 3
	sliceWhere := make(lib.CipherVector, nbrWhere)
	for j := 0; j < nbrWhere; j++ {
		sliceWhere[j] = *lib.EncryptInt(el.Aggregate, val)

	}

	sliceWhere1 := make(lib.CipherVector, nbrWhere)
	for j := 0; j < nbrWhere; j++ {
		sliceWhere1[j] = *lib.EncryptInt(el.Aggregate, val)

	}

	nbrGrp := 3
	sliceGrp := make(lib.CipherVector, nbrGrp)
	for j := 0; j < nbrGrp; j++ {
		sliceGrp[j] = *lib.EncryptInt(el.Aggregate, val)

	}

	nbrAggr := 1
	aggr := make(lib.CipherVector, nbrAggr)
	for j := 0; j < nbrAggr; j++ {
		aggr[j] = *lib.EncryptInt(el.Aggregate, val)

	}

	data = append(data, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr}, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr}, lib.ProcessResponse{WhereEnc: sliceWhere1, AggregatingAttributes: aggr})

	wg := lib.StartParallelize(1)

	result1 := lib.FilteredResponse{}
	go func() {
		defer wg.Done()
		data1 := append(data, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr})
		_, result1, _ = client1.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data1, 1)
	}()
	_, result, err := client.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data, 1)

	if err != nil {
		t.Fatal("Service did not start.", err)
	}

	lib.EndParallelize(wg)

	finalResult := make([]int64, 0)
	expectedResult := []int64{7, 7}

	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result1.AggregatingAttributes)...)

	assert.Equal(t, len(finalResult), len(expectedResult), "The size of the result is different")
	assert.Equal(t, finalResult, expectedResult, "Wrong result")

	log.Lvl1(finalResult)
}

//______________________________________________________________________________________________________________________
// Servers with a different number of DPs
func TestServiceDifferentDPsAggr(t *testing.T) {
	log.Lvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest()
	// generate 3 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(3, true)
	defer local.CloseAll()

	secKey := network.Suite.Scalar().Pick(random.Stream)
	pubKey := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)
	// Send a request to the service
	// For the first server
	client := serviceI2B2.NewUnLynxClient(el.List[0], strconv.Itoa(0))
	client1 := serviceI2B2.NewUnLynxClient(el.List[0], strconv.Itoa(1))

	//For the second server
	client2 := serviceI2B2.NewUnLynxClient(el.List[1], strconv.Itoa(2))
	client3 := serviceI2B2.NewUnLynxClient(el.List[1], strconv.Itoa(3))
	client4 := serviceI2B2.NewUnLynxClient(el.List[1], strconv.Itoa(4))

	sum := []string{"s1"}
	count := false
	whereQueryValues := []lib.WhereQueryAttribute{{Name: "w1", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w2", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w3", Value: *lib.EncryptInt(el.Aggregate, 1)}} // v1, v3 and v5
	pred := "(v0 == v1 || v2 == v3) && v4 == v5"
	groupBy := []string{}

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	nbrDPs[el.List[0].String()] = 2
	nbrDPs[el.List[1].String()] = 3
	nbrDPs[el.List[2].String()] = 0

	data := []lib.ProcessResponse{}
	val := int64(1)

	nbrWhere := 3
	sliceWhere := make(lib.CipherVector, nbrWhere)
	for j := 0; j < nbrWhere; j++ {
		sliceWhere[j] = *lib.EncryptInt(el.Aggregate, val)

	}

	sliceWhere1 := make(lib.CipherVector, nbrWhere)
	for j := 0; j < nbrWhere; j++ {
		sliceWhere1[j] = *lib.EncryptInt(el.Aggregate, val)

	}

	nbrGrp := 3
	sliceGrp := make(lib.CipherVector, nbrGrp)
	for j := 0; j < nbrGrp; j++ {
		sliceGrp[j] = *lib.EncryptInt(el.Aggregate, val)

	}

	nbrAggr := 1
	aggr := make(lib.CipherVector, nbrAggr)
	for j := 0; j < nbrAggr; j++ {
		aggr[j] = *lib.EncryptInt(el.Aggregate, val)

	}

	data = append(data, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr}, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr}, lib.ProcessResponse{WhereEnc: sliceWhere1, AggregatingAttributes: aggr})

	wg := lib.StartParallelize(4)

	result1 := lib.FilteredResponse{}
	result2 := lib.FilteredResponse{}
	result3 := lib.FilteredResponse{}
	result4 := lib.FilteredResponse{}
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
	_, result, err := client.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data, 1)

	if err != nil {
		t.Fatal("Service did not start.", err)
	}

	lib.EndParallelize(wg)

	finalResult := make([]int64, 0)
	expectedResult := []int64{25, 25, 25, 25, 25}

	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result1.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result2.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result3.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result4.AggregatingAttributes)...)

	assert.Equal(t, len(finalResult), len(expectedResult), "The size of the result is different")
	assert.Equal(t, finalResult, expectedResult, "Wrong result")

	log.Lvl1(finalResult)
}

//______________________________________________________________________________________________________________________
// Test a different query and one more node
func TestServiceDifferentQueryAggr(t *testing.T) {
	log.Lvl1("***************************************************************************************************")
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
	client := serviceI2B2.NewUnLynxClient(el.List[0], strconv.Itoa(0))
	client1 := serviceI2B2.NewUnLynxClient(el.List[0], strconv.Itoa(1))

	//For the second server
	client2 := serviceI2B2.NewUnLynxClient(el.List[1], strconv.Itoa(2))
	client3 := serviceI2B2.NewUnLynxClient(el.List[1], strconv.Itoa(3))
	client4 := serviceI2B2.NewUnLynxClient(el.List[1], strconv.Itoa(4))

	//For the fourth server
	client5 := serviceI2B2.NewUnLynxClient(el.List[3], strconv.Itoa(4))

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

	log.Lvl1(finalResult)
}

//______________________________________________________________________________________________________________________
// Servers with a different number of DPs
func TestServiceConcurrentSurveysAggr(t *testing.T) {
	log.Lvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest()
	// generate 3 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(3, true)
	defer local.CloseAll()

	var wg sync.WaitGroup
	numberThreads := 4

	// this is only because the surveys all belong to the same machine
	mutex := &sync.Mutex{}
	for i := 0; i < numberThreads; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			secKey := network.Suite.Scalar().Pick(random.Stream)
			pubKey := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)
			// Send a request to the service
			// For the first server
			client := serviceI2B2.NewUnLynxClient(el.List[0], strconv.Itoa(0))
			client1 := serviceI2B2.NewUnLynxClient(el.List[0], strconv.Itoa(1))

			//For the second server
			client2 := serviceI2B2.NewUnLynxClient(el.List[1], strconv.Itoa(2))
			client3 := serviceI2B2.NewUnLynxClient(el.List[1], strconv.Itoa(3))
			client4 := serviceI2B2.NewUnLynxClient(el.List[1], strconv.Itoa(4))

			sum := []string{"s1"}
			count := false
			whereQueryValues := []lib.WhereQueryAttribute{{Name: "w1", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w2", Value: *lib.EncryptInt(el.Aggregate, 1)}, {Name: "w3", Value: *lib.EncryptInt(el.Aggregate, 1)}} // v1, v3 and v5
			pred := "(v0 == v1 || v2 == v3) && v4 == v5"
			groupBy := []string{}

			nbrDPs := make(map[string]int64)
			//how many data providers for each server
			nbrDPs[el.List[0].String()] = 2
			nbrDPs[el.List[1].String()] = 3
			nbrDPs[el.List[2].String()] = 0

			data := []lib.ProcessResponse{}
			val := int64(1)

			nbrWhere := 3
			sliceWhere := make(lib.CipherVector, nbrWhere)
			for j := 0; j < nbrWhere; j++ {
				sliceWhere[j] = *lib.EncryptInt(el.Aggregate, val)

			}

			sliceWhere1 := make(lib.CipherVector, nbrWhere)
			for j := 0; j < nbrWhere; j++ {
				sliceWhere1[j] = *lib.EncryptInt(el.Aggregate, val)

			}

			nbrGrp := 3
			sliceGrp := make(lib.CipherVector, nbrGrp)
			for j := 0; j < nbrGrp; j++ {
				sliceGrp[j] = *lib.EncryptInt(el.Aggregate, val)

			}

			nbrAggr := 1
			aggr := make(lib.CipherVector, nbrAggr)
			for j := 0; j < nbrAggr; j++ {
				aggr[j] = *lib.EncryptInt(el.Aggregate, val)

			}

			data = append(data, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr}, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr}, lib.ProcessResponse{WhereEnc: sliceWhere1, AggregatingAttributes: aggr})

			wg1 := lib.StartParallelize(4)

			result1 := lib.FilteredResponse{}
			result2 := lib.FilteredResponse{}
			result3 := lib.FilteredResponse{}
			result4 := lib.FilteredResponse{}
			go func() {
				defer wg1.Done()
				data1 := append(data, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr})
				_, result1, _ = client1.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"+strconv.Itoa(i)), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data1, 1)
			}()
			go func() {
				defer wg1.Done()
				data2 := append(data, data...)
				_, result2, _ = client2.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"+strconv.Itoa(i)), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data2, 1)
			}()
			go func() {
				defer wg1.Done()
				data3 := append(data, data...)
				_, result3, _ = client3.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"+strconv.Itoa(i)), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data3, 1)
			}()
			go func() {
				defer wg1.Done()
				data4 := append(data, data...)
				_, result4, _ = client4.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"+strconv.Itoa(i)), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data4, 1)
			}()
			_, result, err := client.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"+strconv.Itoa(i)), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data, 1)

			if err != nil {
				t.Fatal("Service did not start.", err)
			}

			lib.EndParallelize(wg1)

			finalResult := make([]int64, 0)
			expectedResult := []int64{25, 25, 25, 25, 25}

			mutex.Lock()
			finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result.AggregatingAttributes)...)
			finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result1.AggregatingAttributes)...)
			finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result2.AggregatingAttributes)...)
			finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result3.AggregatingAttributes)...)
			finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result4.AggregatingAttributes)...)
			mutex.Unlock()

			assert.Equal(t, len(finalResult), len(expectedResult), "The size of the result is different")
			assert.Equal(t, finalResult, expectedResult, "Wrong result")

			log.Lvl1(finalResult)
		}(i)
	}
	wg.Wait()
}
