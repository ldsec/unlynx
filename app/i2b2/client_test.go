package main

import (
	"bytes"
	"encoding/xml"
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/app"
	"gopkg.in/dedis/onet.v1/log"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
)

var clientSecKey abstract.Scalar
var clientPubKey abstract.Point
var local *onet.LocalTest
var el *onet.Roster

var nbrTerms = 50

// SETUP / TEARDOWN FUNCTIONS
// ----------------------------------------------------------
func testRemoteSetup() {
	log.SetDebugVisible(1)

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
}

func testLocalSetup() {
	log.SetDebugVisible(1)

	log.LLvl1("***************************************************************************************************")
	os.Remove("pre_compute_multiplications.gob")

	clientSecKey, clientPubKey = lib.GenKey()

	local = onet.NewLocalTest()
	_, el, _ = local.GenTree(3, true)
}

func testLocalTeardown() {
	os.Remove("pre_compute_multiplications.gob")
	local.CloseAll()
}

// UTILITY FUNCTIONS
// ----------------------------------------------------------
func getXMLReaderDDTRequest(t *testing.T, variant int) io.Reader {

	/*
		<unlynx_ddt_request>
		    <id>request ID</id>
		    <enc_values>
			<enc_value>adfw25e4f85as4fas57f=</enc_value>
			<enc_value>ADA5D4D45ESAFD5FDads=</enc_value>
		    </enc_values>
		</unlynx_ddt_request>
	*/

	// enc query terms (encrypted with client public key)
	encDDTTermsSlice := make([]string, 0)
	encDDTTermsXML := ""

	for i := 0; i < nbrTerms; i++ {
		val := (*lib.EncryptInt(el.Aggregate, int64(i))).Serialize()
		encDDTTermsSlice = append(encDDTTermsSlice, val)
		encDDTTermsXML += "<enc_value>" + val + "</enc_value>"
	}

	queryID := "query_ID_XYZf" + strconv.Itoa(variant)

	xmlReader := strings.NewReader(`<unlynx_ddt_request>
						<id>` + queryID + `</id>
						<enc_values>` +
		encDDTTermsXML +
		`</enc_values>
					</unlynx_ddt_request>`)

	log.LLvl1("Generated DDTRequest XML:", xmlReader)

	return xmlReader
}

func getXMLReaderDDTRequestV2(t *testing.T, variant int) io.Reader {

	/*
		<unlynx_ddt_request>
		    <id>request ID</id>
		    <enc_values>
			<enc_value>adfw25e4f85as4fas57f=</enc_value>
			<enc_value>ADA5D4D45ESAFD5FDads=</enc_value>
		    </enc_values>
		</unlynx_ddt_request>
	*/

	// enc query terms (encrypted with client public key)
	encDDTTermsSlice := make([]string, 0)
	encDDTTermsXML := ""

	for i := 0; i < nbrTerms; i++ {
		val := (*lib.EncryptInt(el.Aggregate, int64(i))).Serialize()
		encDDTTermsSlice = append(encDDTTermsSlice, val)
		encDDTTermsXML += "<enc_value>" + val + "</enc_value>"
	}

	queryID := "query_ID_XYZf" + strconv.Itoa(variant)

	var stringBuf bytes.Buffer

	stringBuf.WriteString(`<unlynx_ddt_request>
				<id>` + queryID + `</id>
				<enc_values>` + encDDTTermsXML + `</enc_values>
			       </unlynx_ddt_request>`)

	log.LLvl1("Generated DDTRequest XML v2:", stringBuf.String())
	return strings.NewReader(stringBuf.String())
}

func getXMLReaderAggRequest(t *testing.T, nbrFlags int) io.Reader {

	/*
		<unlynx_agg_request>
		    <id>request ID</id>
		    <client_public_key>5D4D45ESAFD5FDads==</client_public_key>
		    <enc_dummy_flags>
			<enc_dummy_flag>adfw25e4f85as4fas57f=</enc_dummy_flag>
			<enc_dummy_flag>ADA5D4D45ESAFD5FDads=</enc_dummy_flag>
		    </enc_dummy_flags>
		</unlynx_agg_request>
	*/

	// client public key serialization
	clientPubKeyB64, err := lib.SerializeElement(clientPubKey)
	assert.True(t, err == nil)

	// enc query terms (encrypted with client public key)
	encFlagsSlice := make([]string, 0)
	encFlagsXML := ""

	for i := 0; i < nbrFlags; i++ {
		val := (*lib.EncryptInt(el.Aggregate, int64(1))).Serialize()
		encFlagsSlice = append(encFlagsSlice, val)
		encFlagsXML += "<enc_dummy_flag>" + val + "</enc_dummy_flag>"
	}

	queryID := "query_ID_XYZf"

	xmlReader := strings.NewReader(`<unlynx_agg_request>
						<id>` + queryID + `</id>
						<client_public_key>` + clientPubKeyB64 + `</client_public_key>
						<enc_dummy_flags>` +
		encFlagsXML +
		`</enc_dummy_flags>
					</unlynx_agg_request>`)

	log.LLvl1("Generated AggRequest XML:", xmlReader)

	return xmlReader
}

func getXMLReaderAggRequestV2(t *testing.T, nbrFlags int) io.Reader {

	/*
		<unlynx_agg_request>
		    <id>request ID</id>
		    <client_public_key>5D4D45ESAFD5FDads==</client_public_key>
		    <enc_dummy_flags>
			<enc_dummy_flag>adfw25e4f85as4fas57f=</enc_dummy_flag>
			<enc_dummy_flag>ADA5D4D45ESAFD5FDads=</enc_dummy_flag>
		    </enc_dummy_flags>
		</unlynx_agg_request>
	*/

	// client public key serialization
	clientPubKeyB64, err := lib.SerializeElement(clientPubKey)
	assert.True(t, err == nil)

	// enc query terms (encrypted with client public key)
	encFlagsSlice := make([]string, 0)
	encFlagsXML := ""

	for i := 0; i < nbrFlags; i++ {
		val := (*lib.EncryptInt(el.Aggregate, int64(1))).Serialize()
		encFlagsSlice = append(encFlagsSlice, val)
		encFlagsXML += "<enc_dummy_flag>" + val + "</enc_dummy_flag>"
	}

	queryID := "query_ID_XYZf"

	var stringBuf bytes.Buffer

	stringBuf.WriteString(`<unlynx_agg_request>
					<id>` + queryID + `</id>
					<client_public_key>` + clientPubKeyB64 + `</client_public_key>
					<enc_dummy_flags>` + encFlagsXML + `</enc_dummy_flags>
			       </unlynx_agg_request>`)

	log.LLvl1("Generated AggRequest XML v2:", stringBuf.String())
	return strings.NewReader(stringBuf.String())
}

func parseDTTResponse(t *testing.T, xmlString string) lib.XMLMedCoDTTResponse {
	parsed_xml := lib.XMLMedCoDTTResponse{}

	err := xml.Unmarshal([]byte(xmlString), &parsed_xml)
	assert.Equal(t, err, nil)

	return parsed_xml
}

func parseAggResponse(t *testing.T, xmlString string) lib.XMLMedCoAggResponse {
	parsed_xml := lib.XMLMedCoAggResponse{}
	err := xml.Unmarshal([]byte(xmlString), &parsed_xml)
	assert.Equal(t, err, nil)

	return parsed_xml
}

// DDT TEST FUNCTIONS
// ----------------------------------------------------------
func TestMedcoDDTRequest(t *testing.T) {
	testLocalSetup()

	// Start queriers (3 nodes)
	wg := lib.StartParallelize(2)
	var writer, writer1, writer2 bytes.Buffer

	go func() {
		defer wg.Done()
		err1 := unlynxDDTRequest(getXMLReaderDDTRequest(t, 1), &writer1, el, 1, false, true)
		assert.True(t, err1 == nil)
	}()
	go func() {
		defer wg.Done()
		err2 := unlynxDDTRequest(getXMLReaderDDTRequest(t, 2), &writer2, el, 2, false, true)
		assert.True(t, err2 == nil)
	}()
	err := unlynxDDTRequest(getXMLReaderDDTRequest(t, 0), &writer, el, 0, false, true)
	assert.True(t, err == nil)
	lib.EndParallelize(wg)

	// Check results
	finalResponses := make([]lib.XMLMedCoDTTResponse, 0)

	finalResponses = append(finalResponses, parseDTTResponse(t, writer.String()))
	finalResponses = append(finalResponses, parseDTTResponse(t, writer1.String()))
	finalResponses = append(finalResponses, parseDTTResponse(t, writer2.String()))

	for i, response := range finalResponses {
		assert.True(t, response.Error == "")
		assert.Equal(t, len(response.TaggedValues), nbrTerms, "("+string(i)+") The number of tags is different from the number of initial terms")

		for _, el := range response.TaggedValues {

			for j := i + 1; j < len(finalResponses); j++ {
				assert.NotContains(t, finalResponses[j].TaggedValues, el, "There are tags that are the same among nodes")
			}
		}

	}

	testLocalTeardown()
}

func TestMedCoDDTRequestV2(t *testing.T) {
	testLocalSetup()

	// Start queriers (3 nodes)
	wg := lib.StartParallelize(2)
	var writer, writer1, writer2 bytes.Buffer

	go func() {
		defer wg.Done()
		err1 := unlynxDDTRequest(getXMLReaderDDTRequestV2(t, 1), &writer1, el, 1, false, true)
		assert.True(t, err1 == nil)
	}()
	go func() {
		defer wg.Done()
		err2 := unlynxDDTRequest(getXMLReaderDDTRequestV2(t, 2), &writer2, el, 2, false, true)
		assert.True(t, err2 == nil)
	}()
	err := unlynxDDTRequest(getXMLReaderDDTRequestV2(t, 0), &writer, el, 0, false, true)
	assert.True(t, err == nil)
	lib.EndParallelize(wg)

	// Check results
	finalResponses := make([]lib.XMLMedCoDTTResponse, 0)

	finalResponses = append(finalResponses, parseDTTResponse(t, writer.String()))
	finalResponses = append(finalResponses, parseDTTResponse(t, writer1.String()))
	finalResponses = append(finalResponses, parseDTTResponse(t, writer2.String()))

	for i, response := range finalResponses {
		assert.True(t, response.Error == "")
		assert.Equal(t, len(response.TaggedValues), nbrTerms, "("+string(i)+") The number of tags is different from the number of initial terms")

		for _, el := range response.TaggedValues {
			for j := i + 1; j < len(finalResponses); j++ {
				assert.NotContains(t, finalResponses[j].TaggedValues, el, "There are tags that are the same among nodes")
			}
		}

	}
	testLocalTeardown()
}

func TestMedCoDDTRequestRemote(t *testing.T) {
	t.Skip()
	testRemoteSetup()

	// start queries
	wg := lib.StartParallelize(2)
	var writer, writer1, writer2 bytes.Buffer

	go func() {
		defer wg.Done()
		err1 := unlynxDDTRequest(getXMLReaderDDTRequest(t, 1), &writer1, el, 1, false, true)
		assert.True(t, err1 == nil)
	}()
	go func() {
		defer wg.Done()
		err2 := unlynxDDTRequest(getXMLReaderDDTRequest(t, 2), &writer2, el, 2, false, true)
		assert.True(t, err2 == nil)
	}()

	err := unlynxDDTRequest(getXMLReaderDDTRequest(t, 0), &writer, el, 0, false, true)
	assert.True(t, err == nil)
	lib.EndParallelize(wg)

	// Check results
	finalResponses := make([]lib.XMLMedCoDTTResponse, 0)

	finalResponses = append(finalResponses, parseDTTResponse(t, writer.String()))
	finalResponses = append(finalResponses, parseDTTResponse(t, writer1.String()))
	finalResponses = append(finalResponses, parseDTTResponse(t, writer2.String()))

	for i, response := range finalResponses {
		assert.True(t, response.Error == "")
		assert.Equal(t, len(response.TaggedValues), nbrTerms, "("+string(i)+") The number of tags is different from the number of initial terms")

		for _, el := range response.TaggedValues {

			for j := i + 1; j < len(finalResponses); j++ {
				assert.Contains(t, finalResponses[j].TaggedValues, el, "There are tags that are the same among nodes")
			}

		}

	}
}

// AGG TEST FUNCTIONS
func TestLocalAggregate(t *testing.T) {
	secKey, pubKey := lib.GenKey()

	sizeVector := 10
	realResult := int64(0)

	listEncElements := make(lib.CipherVector, 0)
	for i := 0; i < sizeVector; i++ {
		listEncElements = append(listEncElements, *lib.EncryptInt(pubKey, int64(1)))
		realResult += int64(1)
	}

	result := LocalAggregate(listEncElements, pubKey)

	resultDec := lib.DecryptInt(secKey, *result)

	assert.Equal(t, realResult, resultDec)
}

func TestMedcoAggRequest(t *testing.T) {
	testLocalSetup()

	// Start queriers (3 nodes)
	wg := lib.StartParallelize(2)
	var writer, writer1, writer2 bytes.Buffer

	go func() {
		defer wg.Done()
		err1 := unlynxAggRequest(getXMLReaderAggRequest(t, 20), &writer1, el, 1, false)
		assert.True(t, err1 == nil)
	}()
	go func() {
		defer wg.Done()
		err2 := unlynxAggRequest(getXMLReaderAggRequest(t, 50), &writer2, el, 2, false)
		assert.True(t, err2 == nil)
	}()
	err := unlynxAggRequest(getXMLReaderAggRequest(t, 30), &writer, el, 0, false)
	assert.True(t, err == nil)
	lib.EndParallelize(wg)

	// Check results
	finalResponses := make([]lib.XMLMedCoAggResponse, 0)

	finalResponses = append(finalResponses, parseAggResponse(t, writer.String()))
	finalResponses = append(finalResponses, parseAggResponse(t, writer1.String()))
	finalResponses = append(finalResponses, parseAggResponse(t, writer2.String()))

	expectedResponses := [3]int64{20, 30, 50}
	for i, response := range finalResponses {
		assert.True(t, response.Error == "")
		aux := lib.CipherText{}
		err := aux.Deserialize(finalResponses[i].AggregateV)
		assert.Nil(t, err)

		assert.Contains(t, expectedResponses, lib.DecryptInt(clientSecKey, aux), "Aggregation result does not match")
	}

	testLocalTeardown()
}

func TestMedCoAggRequestV2(t *testing.T) {
	testLocalSetup()

	// Start queriers (3 nodes)
	wg := lib.StartParallelize(2)
	var writer, writer1, writer2 bytes.Buffer

	go func() {
		defer wg.Done()
		err1 := unlynxAggRequest(getXMLReaderAggRequestV2(t, 100), &writer1, el, 1, false)
		assert.True(t, err1 == nil)
	}()
	go func() {
		defer wg.Done()
		err2 := unlynxAggRequest(getXMLReaderAggRequestV2(t, 4), &writer2, el, 2, false)
		assert.True(t, err2 == nil)
	}()
	err := unlynxAggRequest(getXMLReaderAggRequestV2(t, 7), &writer, el, 0, false)
	assert.True(t, err == nil)
	lib.EndParallelize(wg)

	// Check results
	finalResponses := make([]lib.XMLMedCoAggResponse, 0)

	finalResponses = append(finalResponses, parseAggResponse(t, writer.String()))
	finalResponses = append(finalResponses, parseAggResponse(t, writer1.String()))
	finalResponses = append(finalResponses, parseAggResponse(t, writer2.String()))

	expectedResponses := [3]int64{100, 7, 4}
	for i, response := range finalResponses {
		assert.True(t, response.Error == "")
		aux := lib.CipherText{}
		err := aux.Deserialize(finalResponses[i].AggregateV)
		assert.Nil(t, err)

		assert.Contains(t, expectedResponses, lib.DecryptInt(clientSecKey, aux), "Aggregation result does not match")
	}

	testLocalTeardown()
}

func TestMedCoAggRequestRemote(t *testing.T) {
	t.Skip()
	testRemoteSetup()

	// start queries
	wg := lib.StartParallelize(2)
	var writer, writer1, writer2 bytes.Buffer

	go func() {
		defer wg.Done()
		err1 := unlynxAggRequest(getXMLReaderAggRequest(t, 3), &writer1, el, 1, false)
		assert.True(t, err1 == nil)
	}()
	go func() {
		defer wg.Done()
		err2 := unlynxAggRequest(getXMLReaderAggRequest(t, 47), &writer2, el, 2, false)
		assert.True(t, err2 == nil)
	}()

	err := unlynxAggRequest(getXMLReaderAggRequest(t, 31), &writer, el, 0, false)
	assert.True(t, err == nil)
	lib.EndParallelize(wg)

	// Check results
	finalResponses := make([]lib.XMLMedCoAggResponse, 0)

	finalResponses = append(finalResponses, parseAggResponse(t, writer.String()))
	finalResponses = append(finalResponses, parseAggResponse(t, writer1.String()))
	finalResponses = append(finalResponses, parseAggResponse(t, writer2.String()))

	expectedResponses := [3]int64{3, 47, 31}
	for i, response := range finalResponses {
		assert.True(t, response.Error == "")
		aux := lib.CipherText{}
		err := aux.Deserialize(finalResponses[i].AggregateV)
		assert.Nil(t, err)

		assert.Contains(t, expectedResponses, lib.DecryptInt(clientSecKey, aux), "Aggregation result does not match")
	}
}
