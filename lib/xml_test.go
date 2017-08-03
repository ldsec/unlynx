package lib_test

import (
	"testing"

	"github.com/lca1/unlynx/lib"

	"encoding/xml"
	"github.com/stretchr/testify/assert"
)

func TestQueryXML(t *testing.T) {

	xmlString := `<medco_query>
	<id>query ID</id>
	<predicate>some predicate</predicate>
	<enc_where_values>encrypted where query values</enc_where_values>

	<enc_patients_data>
	<patient>
	<enc_data>enc</enc_data>
	<enc_data>enc</enc_data>
	<enc_data>enc</enc_data>
	</patient>
	<patient>
	<enc_data>enc</enc_data>
	<enc_data>enc</enc_data>
	<enc_data>enc</enc_data>
	</patient>
	</enc_patients_data>

	<client_public_key>base64 encoded key</client_public_key>
	<result_mode> result mode (0 or 1)</result_mode>
	</medco_query>`

	parsed_xml := lib.XMLMedCoQuery{}
	err := xml.Unmarshal([]byte(xmlString), &parsed_xml)
	assert.Equal(t, err, nil)
	assert.Equal(t, parsed_xml.Predicate, "some predicate")
	assert.Equal(t, parsed_xml.EncWhereValues, "encrypted where query values")
	assert.Equal(t, parsed_xml.ClientPublicKeyB64, "base64 encoded key")
	assert.Equal(t, parsed_xml.ResultMode, " result mode (0 or 1)")
	assert.NotEqual(t, parsed_xml.ResultMode, parsed_xml.EncWhereValues)
	assert.Equal(t, parsed_xml.EncPatientsData[0].EncData[0], "enc")
	assert.Equal(t, parsed_xml.EncPatientsData[0].EncData[1], "enc")
	assert.Equal(t, parsed_xml.EncPatientsData[0].EncData[2], "enc")
	assert.Equal(t, parsed_xml.EncPatientsData[1].EncData[0], "enc")
	assert.Equal(t, parsed_xml.EncPatientsData[1].EncData[1], "enc")
	assert.Equal(t, parsed_xml.EncPatientsData[1].EncData[2], "enc")
}

func TestQueryResultXML(t *testing.T) {

	xmlString := `<medco_query_result>
	<id>query ID</id>
	<result_mode> result mode (0 or 1)</result_mode>
	<enc_result>encrypted result</enc_result>
	<error>a message error (only if error, the enc_result will be empty)
</error></medco_query_result>`

	parsed_xml := lib.XMLMedCoQueryResult{}
	err := xml.Unmarshal([]byte(xmlString), &parsed_xml)
	assert.Equal(t, err, nil)
	assert.Equal(t, parsed_xml.QueryID, "query ID")
	assert.Equal(t, parsed_xml.EncResult, "encrypted result")
	assert.Equal(t, parsed_xml.ResultMode, " result mode (0 or 1)")
	assert.Equal(t, parsed_xml.Error, `a message error (only if error, the enc_result will be empty)
`)
}

func TestQueryResultXMLNoError(t *testing.T) {

	xmlString := `<medco_query_result>
	<id>query ID</id>
	<result_mode> result mode (0 or 1)</result_mode>
	<enc_result>encrypted result</enc_result>
</medco_query_result>`

	parsed_xml := lib.XMLMedCoQueryResult{}
	err := xml.Unmarshal([]byte(xmlString), &parsed_xml)
	assert.Equal(t, err, nil)
	assert.Equal(t, parsed_xml.QueryID, "query ID")
	assert.Equal(t, parsed_xml.EncResult, "encrypted result")
	assert.Equal(t, parsed_xml.ResultMode, " result mode (0 or 1)")
	assert.Equal(t, parsed_xml.Error, "")
}
