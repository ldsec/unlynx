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
	"testing"
)

func TestServiceShuffle(t *testing.T) {
	log.LLvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest()
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(3, true)
	defer local.CloseAll()

	secKey := network.Suite.Scalar().Pick(random.Stream)
	pubKey := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)
	// Send a request to the service
	client := serviceI2B2.NewMedcoClient(el.List[0], strconv.Itoa(0))
	client1 := serviceI2B2.NewMedcoClient(el.List[1], strconv.Itoa(0))
	client2 := serviceI2B2.NewMedcoClient(el.List[2], strconv.Itoa(0))

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
	go func(i int) {
		defer wg.Done()
		data1 := append(data, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr})
		_, result1, _ = client1.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true, sum, count, whereQueryValues, pred, groupBy, data1, 0)
	}(0)
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

	log.LLvl1(finalResult)
}

func TestServiceAggr(t *testing.T) {
	log.LLvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest()
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(3, true)
	defer local.CloseAll()

	secKey := network.Suite.Scalar().Pick(random.Stream)
	pubKey := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)
	// Send a request to the service
	client := serviceI2B2.NewMedcoClient(el.List[0], strconv.Itoa(0))
	client1 := serviceI2B2.NewMedcoClient(el.List[1], strconv.Itoa(0))
	client2 := serviceI2B2.NewMedcoClient(el.List[2], strconv.Itoa(0))

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
	go func(i int) {
		defer wg.Done()
		data1 := append(data, lib.ProcessResponse{WhereEnc: sliceWhere, AggregatingAttributes: aggr})
		_, result1, _ = client1.SendSurveyDpQuery(el, serviceI2B2.SurveyID("testSurvey"), serviceI2B2.SurveyID(""), pubKey, nbrDPs, false, true /*this permits to use precomputation for shuffling*/, sum, count, whereQueryValues, pred, groupBy, data1, 1)
	}(0)
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
	expectedResult := []int64{3, 4, 6}

	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result1.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(secKey, &result2.AggregatingAttributes)...)

	assert.Equal(t, len(finalResult), len(expectedResult), "The size of the result is different")

	var check bool
	for ev := range expectedResult {
		check = false
		for fr := range finalResult {
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
