// Package lib contains medco_structs which contains structures and methods built on basic structures defined in crypto
package lib

import (
	"encoding/xml"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
)

// Input XML definition and methods
//______________________________________________________________________________________________________________________

// example of the input XML format
/*
<medco_query>
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
</medco_query>
*/

// XMLMedCoQuery is a parsed XML definition
type XMLMedCoQuery struct {
	XMLName            xml.Name            `xml:"medco_query"`
	QueryID            string              `xml:"id"`
	Predicate          string              `xml:"predicate"`
	EncWhereValues     string              `xml:"enc_where_values"`
	EncPatientsData    []XMLEncPatientData `xml:"enc_patients_data>patient"`
	ClientPublicKeyB64 string              `xml:"client_public_key"`
	ResultMode         string              `xml:"result_mode"`
}

// XMLEncPatientData is a parsed patient data in XML
type XMLEncPatientData struct {
	EncData []string `xml:"enc_data"`
}

// PatientsDataToUnlynxFormat parses and decodes the base64-encoded values in the XML, returns slice of patients ready for input to unlynx
func (xml *XMLMedCoQuery) PatientsDataToUnlynxFormat(el *onet.Roster) ([]ProcessResponse, error) {

	// iter over patients
	patientsProcessResponse := make([]ProcessResponse, len(xml.EncPatientsData))
	for patientIdx, patient := range xml.EncPatientsData {

		// iter over each row of the patient and deserialize
		patientsProcessResponse[patientIdx].WhereEnc = make(CipherVector, len(patient.EncData))
		for encDataIdx, encData := range patient.EncData {

			err := patientsProcessResponse[patientIdx].WhereEnc[encDataIdx].Deserialize(encData)
			if err != nil {
				log.Error("Error while decoding CipherVector.")
				return nil, err
			}
		}

		// TODO: here is generated the encrypted aggregating attribute, hardcoded to 1
		// TODO: this attribute is either 1 or 0 according to the dummy status
		// TODO: thus, this part is to be changed to support dummies in the future
		nbrAggr := 1
		aggr := make(CipherVector, nbrAggr)
		for j := 0; j < nbrAggr; j++ {
			aggr[j] = *EncryptInt(el.Aggregate, int64(1))
		}
		patientsProcessResponse[patientIdx].AggregatingAttributes = aggr
	}

	return patientsProcessResponse, nil
}

// Output XML definition and methods
//______________________________________________________________________________________________________________________

// example of the input XML format
/*
<medco_query_result>
	<id>query ID</id>
	<result_mode> result mode (0 or 1)</result_mode>
	<enc_result>encrypted result</enc_result>
	<error>a message error (only if error, the enc_result will be empty)</error>
</medco_query_result>
*/

// XMLMedCoQueryResult is a parsed XML definition
type XMLMedCoQueryResult struct {
	XMLName    xml.Name `xml:"medco_query_result"`
	QueryID    string   `xml:"id"`
	ResultMode string   `xml:"result_mode"`
	EncResult  string   `xml:"enc_result"`
	Error      string   `xml:"error"`
}
