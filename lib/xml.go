// Package lib contains medco_structs which contains structures and methods built on basic structures defined in crypto
package lib

import (
	"encoding/xml"
	"gopkg.in/dedis/onet.v1/log"
)

// Input XML definition and methods
//______________________________________________________________________________________________________________________

// example of the input XML format for the DDT request
/*
<unlynx_ddt_request>
    <id>request ID</id>
    <enc_values>
        <enc_value>adfw25e4f85as4fas57f=</enc_value>
        <enc_value>ADA5D4D45ESAFD5FDads=</enc_value>
    </enc_values>
</unlynx_ddt_request>
*/

// XMLMedCoDTTRequest is a parsed XML definition for the DDT request
type XMLMedCoDTTRequest struct {
	XMLName          xml.Name `xml:"unlynx_ddt_request"`
	QueryID          string   `xml:"id"`
	XMLEncQueryTerms []string `xml:"enc_values>enc_value"`
}

// DDTRequestToUnlynxFormat parses and decodes the base64-encoded values in the XML, returns a slice of encrypted query terms ready to be inputed in UnLynx
func (xml *XMLMedCoDTTRequest) DDTRequestToUnlynxFormat() (CipherVector, string, error) {

	// iterate over the query paremeters
	encQueryTerms := make(CipherVector, len(xml.XMLEncQueryTerms))

	for _, term := range xml.XMLEncQueryTerms {
		aux := CipherText{}

		err := aux.Deserialize(term)
		if err != nil {
			log.Error("Error while deserializing a CipherText.")
			return nil, "", err
		}

		encQueryTerms = append(encQueryTerms, aux)
	}

	return encQueryTerms, xml.QueryID, nil
}

// example of the input XML format for aggregation request
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

// XMLMedCoAggRequest is a parsed XML definition for the aggregation request
type XMLMedCoAggRequest struct {
	XMLName          xml.Name `xml:"unlynx_agg_request"`
	QueryID          string   `xml:"id"`
	ClientPubKey     string   `xml:"client_public_key"`
	XMLEncDummyFlags []string `xml:"enc_dummy_flags>enc_dummy_flag"`
}

// AggRequestToUnlynxFormat parses and decodes the base64-encoded values in the XML, returns a slice of encrypted values to be aggregated by UnLynx
func (xml *XMLMedCoAggRequest) AggRequestToUnlynxFormat() (CipherVector, string, error) {

	// iterate over the encrypted flag values
	encDummyFlags := make(CipherVector, len(xml.XMLEncDummyFlags))

	for _, encFlag := range xml.XMLEncDummyFlags {
		aux := CipherText{}

		err := aux.Deserialize(encFlag)
		if err != nil {
			log.Error("Error while deserializing a CipherText.")
			return nil, "", err
		}

		encDummyFlags = append(encDummyFlags, aux)
	}

	return encDummyFlags, xml.QueryID, nil
}

// Output XML definition and methods
//______________________________________________________________________________________________________________________

// example of the input XML format definition for the DDT response
/*
<unlynx_ddt_response>
    <id>request ID</id>
    <times unit="ms">{xx: 13, etc}</times>
    <tagged_values>
        <tagged_value>adfw25e457f=</tagged_value>
        <tagged_value>ADfFD5FDads=</tagged_value>
    </tagged_values>
    <error></error>
</unlynx_ddt_response>
*/

// XMLMedCoDTTResponse is a parsed XML definition
type XMLMedCoDTTResponse struct {
	XMLName      xml.Name `xml:"unlynx_ddt_response"`
	QueryID      string   `xml:"id"`
	Times        string   `xml:"times"`
	TaggedValues []string `xml:"tagged_values>tagged_value"`
	Error        string   `xml:"error"`
}

// example of the input XML format definition for the aggregation response
/*
<unlynx_agg_response>
    <id>request ID</id>
    <times>{cc: 55}</times>
    <aggregate>f85as4fas57f=</aggregate>
    <error></error>
</unlynx_agg_response>
*/

// XMLMedCoAggResponse is a parsed XML definition
type XMLMedCoAggResponse struct {
	XMLName    xml.Name `xml:"unlynx_agg_response"`
	QueryID    string   `xml:"id"`
	Times      string   `xml:"times"`
	AggregateV string   `xml:"aggregate"`
	Error      string   `xml:"error"`
}
