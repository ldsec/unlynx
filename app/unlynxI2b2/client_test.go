package main

import (
	"fmt"
	"gopkg.in/dedis/onet.v1"
	"os"
	"testing"

	"github.com/lca1/unlynx/lib"
	"gopkg.in/dedis/onet.v1/log"

	"bytes"
	"encoding/xml"
	"github.com/lca1/unlynx/services/i2b2"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1/app"
	"io"
	"strconv"
	"strings"
	"time"
)

var clientSecKey abstract.Scalar
var clientPubKey abstract.Point
var local *onet.LocalTest
var el *onet.Roster
var aggr lib.CipherVector

// setup / teardown functions
// ----------------------------------------------------------
func testRemoteSetup() {
	log.LLvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	clientSecKey, clientPubKey = lib.GenKey()

	// generate el with group file
	f, err := os.Open("test/group.toml")
	if err != nil {
		log.Error("Error while opening group file", err)
		os.Exit(1)
	}
	el, err = app.ReadGroupToml(f)
	if err != nil {
		log.Error("Error while reading group file", err)
		os.Exit(1)
	}
	if len(el.List) <= 0 {
		log.Error("Empty or invalid group file", err)
		os.Exit(1)
	}

	log.SetDebugVisible(5)

	nbrAggr := 1
	aggr = make(lib.CipherVector, nbrAggr)
	for j := 0; j < nbrAggr; j++ {
		aggr[j] = *lib.EncryptInt(el.Aggregate, int64(1))

	}
}

func testLocalSetup() {
	log.LLvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")
	clientSecKey, clientPubKey = lib.GenKey()
	local = onet.NewLocalTest()
	_, el, _ = local.GenTree(3, true)
	log.SetDebugVisible(1)

	nbrAggr := 1
	aggr = make(lib.CipherVector, nbrAggr)
	for j := 0; j < nbrAggr; j++ {
		aggr[j] = *lib.EncryptInt(el.Aggregate, int64(1))

	}
}

func testLocalTeardown() {
	os.Remove("pre_compute_multiplications.gob")
	local.CloseAll()
}

// utility functions
// ----------------------------------------------------------
func getXMLReader(t *testing.T, variant int) io.Reader {

	// client public key serialization
	clientPubKeyB64, err := lib.SerializeElement(clientPubKey)
	assert.True(t, err == nil)

	// enc where values (encrypted with client public key)
	encWhereValuesSlice := make([]string, 5)
	for i := range encWhereValuesSlice {
		val := (*lib.EncryptInt(el.Aggregate, int64(i))).Serialize()
		encWhereValuesSlice[i] = val
	}
	encWhereValues := "{w0, " + encWhereValuesSlice[0] + ", w1, " + encWhereValuesSlice[1] + ", w2, " + encWhereValuesSlice[2] +
		", w3, " + encWhereValuesSlice[3] + ", w4, " + encWhereValuesSlice[4] + "}"

	// enc patients data (encrypted with cothority public key)
	encDataClearValues := [][]int64{
		[]int64{2, 0, 4},
		[]int64{0, 2, 5},
		[]int64{0, 2, 4, 1, 1, 1, 1, 1},
	}

	encData := make([][]string, len(encDataClearValues))
	for i, vi := range encDataClearValues {
		encData[i] = make([]string, len(vi))
		for j, vj := range encDataClearValues[i] {
			encVal := (*lib.EncryptInt(el.Aggregate, vj)).Serialize()
			encData[i][j] = encVal
		}
	}

	// have different values
	if variant == 0 {

	} else if variant == 1 {
		encData[2][7] = (*lib.EncryptInt(el.Aggregate, int64(99))).Serialize()
	} else if variant == 2 {
		encData[2][5] = (*lib.EncryptInt(el.Aggregate, int64(99))).Serialize()
		encData[1][2] = (*lib.EncryptInt(el.Aggregate, int64(909))).Serialize()
		encData[2][2] = (*lib.EncryptInt(el.Aggregate, int64(9509))).Serialize()
	}

	queryID := "query_ID_XYZf"
	predicate := "(exists(v0, r) || exists(v1, r)) &amp;&amp; (exists(v2, r) || exists(v3, r)) &amp;&amp; exists(v4, r)"
	resultMode := "0"

	xmlReader := strings.NewReader(`<medco_query>
	<id>` + queryID + `</id>
	<predicate>` + predicate + `</predicate>
	<enc_where_values>` + encWhereValues + `</enc_where_values>

	<enc_patients_data>
	<patient>
	<enc_data>` + encData[0][0] + `</enc_data>
	<enc_data>` + encData[0][1] + `</enc_data>
	<enc_data>` + encData[0][2] + `</enc_data>
	</patient>
	<patient>
	<enc_data>` + encData[1][0] + `</enc_data>
	<enc_data>` + encData[1][1] + `</enc_data>
	<enc_data>` + encData[1][2] + `</enc_data>
	</patient>
	<patient>
	<enc_data>` + encData[2][0] + `</enc_data>
	<enc_data>` + encData[2][1] + `</enc_data>
	<enc_data>` + encData[2][2] + `</enc_data>
	<enc_data>` + encData[2][3] + `</enc_data>
	<enc_data>` + encData[2][4] + `</enc_data>
	<enc_data>` + encData[2][5] + `</enc_data>
	<enc_data>` + encData[2][6] + `</enc_data>
	<enc_data>` + encData[2][7] + `</enc_data>
	</patient>
	</enc_patients_data>

	<client_public_key>` + clientPubKeyB64 + `</client_public_key>
	<result_mode>` + resultMode + `</result_mode>
	</medco_query>`)

	log.LLvl1("generated xml:", xmlReader)

	return xmlReader
}

func getXMLReaderV2(t *testing.T) io.Reader {

	// client public key serialization
	clientPubKeyB64, err := lib.SerializeElement(clientPubKey)
	assert.True(t, err == nil)

	// enc where values (encrypted with client public key)
	encWhereValuesSlice := make([]string, 5)
	for i := range encWhereValuesSlice {
		val := (*lib.EncryptInt(el.Aggregate, int64(i))).Serialize()
		encWhereValuesSlice[i] = val
	}
	encWhereValues := "{w0, " + encWhereValuesSlice[0] + ", w1, " + encWhereValuesSlice[1] + ", w2, " + encWhereValuesSlice[2] +
		", w3, " + encWhereValuesSlice[3] + ", w4, " + encWhereValuesSlice[4] + "}"

	// enc patients data (encrypted with cothority public key)
	encDataClearValues := [][]int64{
		[]int64{2, 0, 4},                //1
		[]int64{0, 2, 5},                //0
		[]int64{0, 2, 4, 1, 1, 1, 1, 1}, //1
		[]int64{0, 2, 5},                //0
		[]int64{0, 2, 5},                //0
		[]int64{2, 0, 4},                //1
		[]int64{0, 2, 4, 1, 1, 1, 1, 1}, //1
		[]int64{0, 2, 4, 1, 1, 1, 1, 1}, //1
		[]int64{0, 2, 4, 1, 1, 1, 1, 1}, //1
		[]int64{0, 2, 4, 1, 1, 1, 1, 1}, //1
		[]int64{2, 0, 4},                //1
		[]int64{2, 0, 4},                //1
		[]int64{2, 0, 4},                //1
		[]int64{2, 0, 4},                //1
		[]int64{2, 0, 4},                //1
		[]int64{2, 0, 4},                //1
		[]int64{0, 2, 4, 1, 1, 1, 1, 1}, //1
		[]int64{0, 2, 4, 1, 1, 1, 1, 1}, //1
		[]int64{0, 2, 4, 1, 1, 1, 1, 1}, //1
		[]int64{0, 2, 4, 1, 1, 1, 1, 1}, //1
		[]int64{0, 2, 4, 1, 1, 1, 1, 1}, //1
		[]int64{0, 2, 4, 1, 1, 1, 1, 1}, //1
		[]int64{0, 2, 4, 1, 1, 1, 1, 1}, //1
		[]int64{0, 2, 4, 1, 1, 1, 1, 1}, //1
		[]int64{0, 2, 4, 1, 1, 1, 1, 1}, //1
		[]int64{0, 2, 4, 1, 1, 1, 1, 1}, //1
		[]int64{0, 2, 4, 1, 1, 1, 1, 1}, //1
		[]int64{0, 2, 4, 1, 1, 1, 1, 1}, //1
		[]int64{0, 2, 4, 1, 1, 1, 1, 1}, //1
		[]int64{0, 2, 4, 1, 1, 1, 1, 1}, //1
		[]int64{0, 2, 4, 1, 1, 1, 1, 1}, //1
		[]int64{0, 2, 4, 1, 1, 1, 1, 1}, //1
		[]int64{0, 2, 4, 1, 1, 1, 1, 1}, //1
		[]int64{0, 2, 4, 1, 1, 1, 1, 1}, //1
		[]int64{0, 2, 4, 1, 1, 1, 1, 1}, //1
		[]int64{0, 2, 4, 1, 1, 1, 1, 1}, //1
		[]int64{0, 2, 4, 1, 1, 1, 1, 1}, //1
	}

	encData := make([][]string, len(encDataClearValues))
	for i, vi := range encDataClearValues {
		encData[i] = make([]string, len(vi))
		for j, vj := range encDataClearValues[i] {
			encVal := (*lib.EncryptInt(el.Aggregate, vj)).Serialize()
			encData[i][j] = encVal
		}
	}

	queryID := "query_ID_XYZ"
	predicate := "(exists(v0, r) || exists(v1, r)) &amp;&amp; (exists(v2, r) || exists(v3, r)) &amp;&amp; exists(v4, r)"
	resultMode := "1"

	var stringBuf bytes.Buffer

	stringBuf.WriteString(`<medco_query>
	<id>` + queryID + `</id>
	<predicate>` + predicate + `</predicate>
	<enc_where_values>` + encWhereValues + `</enc_where_values>

	<enc_patients_data>`)

	for _, pdata := range encData {
		stringBuf.WriteString("<patient>")
		for _, rdata := range pdata {
			stringBuf.WriteString("<enc_data>" + rdata + "</enc_data>")
		}
		stringBuf.WriteString("</patient>")
	}

	stringBuf.WriteString(`</enc_patients_data>

	<client_public_key>` + clientPubKeyB64 + `</client_public_key>
	<result_mode>` + resultMode + `</result_mode>
	</medco_query>`)

	log.LLvl1("generated xml v2:", stringBuf.String())
	return strings.NewReader(stringBuf.String())
}

func parseQueryResult(t *testing.T, xmlString string) lib.XMLMedCoQueryResult {
	parsed_xml := lib.XMLMedCoQueryResult{}
	err := xml.Unmarshal([]byte(xmlString), &parsed_xml)
	assert.Equal(t, err, nil)

	return parsed_xml
}

func TestUnlynxQuery(t *testing.T) {
	testLocalSetup()

	// start queries
	wg := lib.StartParallelize(2)
	var writer, writer1, writer2 bytes.Buffer

	go func() {
		defer wg.Done()
		err1 := unlynxQuery(getXMLReader(t, 1), &writer1, el, 1, false)
		assert.True(t, err1 == nil)
	}()
	go func() {
		defer wg.Done()
		err2 := unlynxQuery(getXMLReader(t, 2), &writer2, el, 2, false)
		assert.True(t, err2 == nil)
	}()

	err := unlynxQuery(getXMLReader(t, 0), &writer, el, 0, false)
	assert.True(t, err == nil)
	lib.EndParallelize(wg)

	// check results
	finalResult := make([]int64, 0)
	expectedResult := []int64{2, 2, 1}

	finalResult = append(finalResult, lib.DecryptInt(clientSecKey,
		*lib.NewCipherTextFromBase64(parseQueryResult(t, writer.String()).EncResult)))
	finalResult = append(finalResult, lib.DecryptInt(clientSecKey,
		*lib.NewCipherTextFromBase64(parseQueryResult(t, writer1.String()).EncResult)))
	finalResult = append(finalResult, lib.DecryptInt(clientSecKey,
		*lib.NewCipherTextFromBase64(parseQueryResult(t, writer2.String()).EncResult)))
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

	testLocalTeardown()
}

func TestUnlynxQueryV2(t *testing.T) {
	testLocalSetup()

	// start queries
	wg := lib.StartParallelize(2)
	var writer, writer1, writer2 bytes.Buffer

	go func() {
		defer wg.Done()
		err1 := unlynxQuery(getXMLReaderV2(t), &writer1, el, 1, false)
		assert.True(t, err1 == nil)
	}()
	go func() {
		defer wg.Done()
		err2 := unlynxQuery(getXMLReaderV2(t), &writer2, el, 2, false)
		assert.True(t, err2 == nil)
	}()

	err := unlynxQuery(getXMLReaderV2(t), &writer, el, 0, false)
	assert.True(t, err == nil)

	lib.EndParallelize(wg)

	// check results
	finalResult := make([]int64, 0)
	expectedResult := []int64{102, 102, 102} // mode 1 here

	finalResult = append(finalResult, lib.DecryptInt(clientSecKey,
		*lib.NewCipherTextFromBase64(parseQueryResult(t, writer.String()).EncResult)))
	finalResult = append(finalResult, lib.DecryptInt(clientSecKey,
		*lib.NewCipherTextFromBase64(parseQueryResult(t, writer1.String()).EncResult)))
	finalResult = append(finalResult, lib.DecryptInt(clientSecKey,
		*lib.NewCipherTextFromBase64(parseQueryResult(t, writer2.String()).EncResult)))
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

	testLocalTeardown()
}

// test query, without serialization (xml etc.)
func TestCallSendSurveyDpQuery(t *testing.T) {
	testLocalSetup()

	encWhereValues := []lib.WhereQueryAttribute{
		{Name: "w0", Value: *lib.EncryptInt(el.Aggregate, int64(0))},
		{Name: "w1", Value: *lib.EncryptInt(el.Aggregate, int64(1))},
		{Name: "w2", Value: *lib.EncryptInt(el.Aggregate, int64(2))},
		{Name: "w3", Value: *lib.EncryptInt(el.Aggregate, int64(3))},
		{Name: "w4", Value: *lib.EncryptInt(el.Aggregate, int64(4))},
	}

	patientsData := []lib.ProcessResponse{
		// patient 0
		{
			WhereEnc: lib.CipherVector{
				*lib.EncryptInt(el.Aggregate, int64(2)),
				*lib.EncryptInt(el.Aggregate, int64(0)),
				*lib.EncryptInt(el.Aggregate, int64(4)),
			},
			AggregatingAttributes: aggr,
		},

		// patient 1
		{
			WhereEnc: lib.CipherVector{
				*lib.EncryptInt(el.Aggregate, int64(0)),
				*lib.EncryptInt(el.Aggregate, int64(2)),
				*lib.EncryptInt(el.Aggregate, int64(5)),
			},
			AggregatingAttributes: aggr,
		},

		// patient 2
		{
			WhereEnc: lib.CipherVector{
				*lib.EncryptInt(el.Aggregate, int64(0)),
				*lib.EncryptInt(el.Aggregate, int64(2)),
				*lib.EncryptInt(el.Aggregate, int64(4)),
				*lib.EncryptInt(el.Aggregate, int64(1)),
				*lib.EncryptInt(el.Aggregate, int64(1)),
				*lib.EncryptInt(el.Aggregate, int64(1)),
				*lib.EncryptInt(el.Aggregate, int64(1)),
				*lib.EncryptInt(el.Aggregate, int64(1)),
			},
			AggregatingAttributes: aggr,
		},
	}

	// start queries
	wg := lib.StartParallelize(2)
	result1 := lib.FilteredResponse{}
	result2 := lib.FilteredResponse{}
	go func() {
		defer wg.Done()

		client := serviceI2B2.NewUnLynxClient(el.List[1], strconv.Itoa(1))
		_, result1, _, _ = client.SendSurveyDpQuery(
			el, // entities
			serviceI2B2.SurveyID("query_ID_XYZ"), // surveyGenId
			serviceI2B2.SurveyID(""),             // surveyID
			clientPubKey,                         // clientPubKey
			map[string]int64{el.List[0].String(): 1, el.List[1].String(): 1, el.List[2].String(): 1}, // number of DPs per server
			false,          // compute proofs
			false,          // appFlag: data is passed with query (not via separate file)
			[]string{"s1"}, // aggregating attribute
			false,          // count flag
			encWhereValues, // encrypted where query
			"(exists(v0, r) || exists(v1, r)) && (exists(v2, r) || exists(v3, r)) && exists(v4, r)", // predicate
			[]string{},   // groupBy
			patientsData, // encrypted patients data
			0,
			time.Now()) // mode: 0 (each DP different result) or 1 (everyone same aggregation)

		fmt.Println(result1)
	}()
	go func() {
		defer wg.Done()

		client := serviceI2B2.NewUnLynxClient(el.List[2], strconv.Itoa(2))
		_, result2, _, _ = client.SendSurveyDpQuery(
			el, // entities
			serviceI2B2.SurveyID("query_ID_XYZ"), // surveyGenId
			serviceI2B2.SurveyID(""),             // surveyID
			clientPubKey,                         // clientPubKey
			map[string]int64{el.List[0].String(): 1, el.List[1].String(): 1, el.List[2].String(): 1}, // number of DPs per server
			false,          // compute proofs
			false,          // appFlag: data is passed with query (not via separate file)
			[]string{"s1"}, // aggregating attribute
			false,          // count flag
			encWhereValues, // encrypted where query
			"(exists(v0, r) || exists(v1, r)) && (exists(v2, r) || exists(v3, r)) && exists(v4, r)", // predicate
			[]string{},   // groupBy
			patientsData, // encrypted patients data
			0,
			time.Now()) // mode: 0 (each DP different result) or 1 (everyone same aggregation)

		fmt.Println(result2)
	}()

	client := serviceI2B2.NewUnLynxClient(el.List[0], strconv.Itoa(0))
	_, result, _, err := client.SendSurveyDpQuery(
		el, // entities
		serviceI2B2.SurveyID("query_ID_XYZ"), // surveyGenId
		serviceI2B2.SurveyID(""),             // surveyID
		clientPubKey,                         // clientPubKey
		map[string]int64{el.List[0].String(): 1, el.List[1].String(): 1, el.List[2].String(): 1}, // number of DPs per server
		false,          // compute proofs
		false,          // appFlag: data is passed with query (not via separate file)
		[]string{"s1"}, // aggregating attribute
		false,          // count flag
		encWhereValues, // encrypted where query
		"(exists(v0, r) || exists(v1, r)) && (exists(v2, r) || exists(v3, r)) && exists(v4, r)", // predicate
		[]string{},   // groupBy
		patientsData, // encrypted patients data
		0,
		time.Now()) // mode: 0 (each DP different result) or 1 (everyone same aggregation)

	assert.True(t, err == nil)
	lib.EndParallelize(wg)

	// check results
	finalResult := make([]int64, 0)
	expectedResult := []int64{2, 2, 2}

	finalResult = append(finalResult, lib.DecryptIntVector(clientSecKey, &result.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(clientSecKey, &result1.AggregatingAttributes)...)
	finalResult = append(finalResult, lib.DecryptIntVector(clientSecKey, &result2.AggregatingAttributes)...)
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

	testLocalTeardown()
}

func TestUnlynxQueryRemote(t *testing.T) {
	testRemoteSetup()

	// start queries
	wg := lib.StartParallelize(2)
	var writer, writer1, writer2 bytes.Buffer

	go func() {
		defer wg.Done()
		err1 := unlynxQuery(getXMLReader(t, 1), &writer1, el, 1, false)
		assert.True(t, err1 == nil)
	}()
	go func() {
		defer wg.Done()
		err2 := unlynxQuery(getXMLReader(t, 2), &writer2, el, 2, false)
		assert.True(t, err2 == nil)
	}()

	err := unlynxQuery(getXMLReader(t, 0), &writer, el, 0, false)
	assert.True(t, err == nil)
	lib.EndParallelize(wg)

	// check results
	finalResult := make([]int64, 0)
	expectedResult := []int64{2, 2, 1}

	finalResult = append(finalResult, lib.DecryptInt(clientSecKey,
		*lib.NewCipherTextFromBase64(parseQueryResult(t, writer.String()).EncResult)))
	finalResult = append(finalResult, lib.DecryptInt(clientSecKey,
		*lib.NewCipherTextFromBase64(parseQueryResult(t, writer1.String()).EncResult)))
	finalResult = append(finalResult, lib.DecryptInt(clientSecKey,
		*lib.NewCipherTextFromBase64(parseQueryResult(t, writer2.String()).EncResult)))
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
