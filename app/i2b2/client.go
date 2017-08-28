package main

// I2b2 Unlynx client

import (
	"encoding/xml"
	"github.com/lca1/unlynx/app/i2b2/loader"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/services/i2b2"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/app"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/urfave/cli.v1"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"time"
)

// Loader functions
//______________________________________________________________________________________________________________________

//----------------------------------------------------------------------------------------------------------------------
//#----------------------------------------------- LOAD DATA -----------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------

func loadData(c *cli.Context) error {

	// data set file paths
	clinicalFilePath := c.String("clinical")
	genomicFilePath := c.String("genomic")
	groupFilePath := c.String("file")
	entryPointIdx := c.Int("entryPointIdx")
	listSensitive := c.StringSlice("sensitive")
	replaySize := c.Int("size")

	// generate el with group file
	f, err := os.Open(groupFilePath)
	if err != nil {
		log.Error("Error while opening group file", err)
		return cli.NewExitError(err, 1)
	}
	el, err := app.ReadGroupToml(f)
	if err != nil {
		log.Error("Error while reading group file", err)
		return cli.NewExitError(err, 1)
	}
	if len(el.List) <= 0 {
		log.Error("Empty or invalid group file", err)
		return cli.NewExitError(err, 1)
	}

	fClinical, err := os.Open(clinicalFilePath)
	if err != nil {
		log.Error("Error while opening the clinical file", err)
		return cli.NewExitError(err, 1)
	}

	fGenomic, err := os.Open(genomicFilePath)
	if err != nil {
		log.Error("Error while opening the genomic file", err)
		return cli.NewExitError(err, 1)
	}

	if listSensitive == nil {
		log.Error("Error while parsing list of sensitive files", err)
		return cli.NewExitError(err, 1)
	}

	if replaySize < 1 {
		log.Error("Wrong file size value (1>)", err)
		return cli.NewExitError(err, 1)
	}

	loader.LoadClient(el, entryPointIdx, fClinical, fGenomic, listSensitive, replaySize)

	return nil
}

// Client functions
//______________________________________________________________________________________________________________________

//----------------------------------------------------------------------------------------------------------------------
//#----------------------------------------------- DDT REQUEST ---------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------

// read from a reader an xml (until EOF), and unmarshal it
func readDDTRequestXMLFrom(input io.Reader) (*lib.XMLMedCoDTTRequest, error) {

	// read from stdin TODO: limit the amount read
	dataBytes, errIo := ioutil.ReadAll(input)

	if errIo != nil {
		log.Error("Error while reading standard input.", errIo)
		return nil, errIo
	}

	log.Info("Correctly read standard input until EOF.")

	// unmarshal xml (assumes bytes are UTF-8 encoded)
	parsedXML := lib.XMLMedCoDTTRequest{}

	errXML := xml.Unmarshal(dataBytes, &parsedXML)
	if errXML != nil {
		return nil, errXML
	}

	return &parsedXML, nil
}

func unlynxRequestFromApp(c *cli.Context) error {

	// cli arguments
	groupFilePath := c.String("file")
	// TODO: use the serverIdentityID / UUID + el.Search rather than the entry point index
	entryPointIdx := c.Int("entryPointIdx")
	proofs := c.Bool("proofs")

	// generate el with group file
	f, err := os.Open(groupFilePath)
	if err != nil {
		log.Error("Error while opening group file", err)
		return cli.NewExitError(err, 1)
	}
	el, err := app.ReadGroupToml(f)
	if err != nil {
		log.Error("Error while reading group file", err)
		return cli.NewExitError(err, 1)
	}
	if len(el.List) <= 0 {
		log.Error("Empty or invalid group file", err)
		return cli.NewExitError(err, 1)
	}

	// check which message we have: a DDTRequest or a AggRequest
	_, err = readDDTRequestXMLFrom(os.Stdin)
	if err == nil {

		err = unlynxDDTRequest(os.Stdin, os.Stdout, el, entryPointIdx, proofs)
		if err != nil {
			log.Error("Error while querying Unlynx", err)
			return cli.NewExitError(err, 2)
		}

		return nil
	}

	// TODO: need to do the agg request parser

	log.Error("Error while unmarshalling xml.", err)
	return err
}

// TODO: no log.Fatal in general (this stops immediately)
// TODO: handle errors in to/from bytes in crypto.go
// run DDT of query parameters, all errors will be sent to the output
func unlynxDDTRequest(input io.Reader, output io.Writer, el *onet.Roster, entryPointIdx int, proofs bool) error {
	start := time.Now()

	// get data from input
	xmlQuery, err := readDDTRequestXMLFrom(input)

	if err != nil {
		log.Error("Error parsing DDTRequest XML.", err)
		writeDDTResponseXML(output, nil, nil, nil, err)
		return err
	}

	// get formatted data
	encQueryTerms, id, err := xmlQuery.DDTRequestToUnlynxFormat()
	if err != nil {
		log.Error("Error extracing patients data.", err)
		writeDDTResponseXML(output, nil, nil, nil, err)
		return err
	}

	parsingTime := time.Since(start)

	// launch query
	start = time.Now()

	client := serviceI2B2.NewUnLynxClient(el.List[entryPointIdx], strconv.Itoa(entryPointIdx))
	_, result, tr, err := client.SendSurveyDDTRequestTerms(
		el, // Roster
		serviceI2B2.SurveyID(id), // SurveyID
		encQueryTerms,            // Encrypted query terms to tag
		proofs,                   // compute proofs?
	)

	totalTime := time.Since(start)

	if err != nil {
		log.Error("Error during the DDTRequest service.", err)
		writeDDTResponseXML(output, nil, nil, nil, err)
		return err
	}

	// sanity check
	if len(result) == 0 || len(result) != len(encQueryTerms) {
		log.Error("The number of tags", len(result), "does not match the number of terms", len(encQueryTerms), ".", err)
	}

	tr.DDTResquestTimeCommun = totalTime - tr.DDTRequestTimeExec
	tr.DDTparsingTime = parsingTime
	tr.DDTRequestTimeExec += tr.DDTparsingTime

	err = writeDDTResponseXML(output, xmlQuery, result, &tr, nil)
	if err != nil {
		log.Error("Error while writing result.", err)
		writeDDTResponseXML(output, nil, nil, nil, err)
		return err
	}
	return nil
}

// output result xml on a writer (if result_err != nil, the error is sent)
func writeDDTResponseXML(output io.Writer, xmlQuery *lib.XMLMedCoDTTRequest, result []lib.GroupingKey, tr *serviceI2B2.TimeResults, err error) error {

	/*
		<unlynx_ddt_response>
		    <id>request ID</id>
		    <times unit="ms">{xx: 13, etc}</times>
		    <tagged_values>
			<tagged_value>adfw25e457f=</tagged_value>
			<tagged_value>ADfFD5FDads=</tagged_value>
		    </tagged_values>
		</unlynx_ddt_response>
	*/

	resultString := ""
	if err == nil && xmlQuery != nil {
		resultTags := ""

		for _, tag := range result {
			resultTags += "<tagged_value>" + string(tag) + "</tagged_value>"

		}

		resultString = `<unlynx_ddt_response>
					<id>` + (*xmlQuery).QueryID + `</id>
					<times unit="ms">{"DDTRequest execution time":` + strconv.FormatInt(int64(tr.DDTRequestTimeExec.Nanoseconds()/1000000.0), 10) +
			`,"DDTRequest communication time":` + strconv.FormatInt(int64(tr.DDTResquestTimeCommun.Nanoseconds()/1000000.0), 10) +
			`,"DDTRequest parsing time":` + strconv.FormatInt(int64(tr.DDTparsingTime.Nanoseconds()/1000000.0), 10) +
			`}</times>
					<tagged_values>` + resultTags + `</tagged_values>
					<error></error>
				</unlynx_ddt_response>`
	} else if xmlQuery != nil {
		resultString = `<unlynx_ddt_response>
					<id>` + (*xmlQuery).QueryID + `</id>
					<error>` + err.Error() + `</error>
				</unlynx_ddt_response>`
	} else {
		resultString = `<unlynx_ddt_response>
					<id>unknown</id>
					<error>` + err.Error() + `</error>
				</unlynx_ddt_response>`
	}

	_, err = io.WriteString(output, resultString)
	if err != nil {
		log.Error("Error while writing result.", err)
		return err
	}
	return nil
}

//----------------------------------------------------------------------------------------------------------------------
//#----------------------------------------------- AGG REQUEST ----------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------

// read from a reader an xml (until EOF), and unmarshal it
/*func readAggRequestXMLFrom(input io.Reader) (*lib.XMLMedCoAggRequest, error) {

	// read from stdin TODO: limit the amount read
	dataBytes, errIo := ioutil.ReadAll(input)

	if errIo != nil {
		log.Error("Error while reading standard input.", errIo)
		return nil, errIo
	}

	log.Info("Correctly read standard input until EOF.")

	// unmarshal xml (assumes bytes are UTF-8 encoded)
	parsedXML := lib.XMLMedCoAggRequest{}
	errXML := xml.Unmarshal(dataBytes, &parsedXML)
	if errXML != nil {
		log.Error("Error while unmarshalling DDTRequest xml.", errXML)
		return nil, errXML
	}

	return &parsedXML, nil
}*/

func unlynxAggRequestFromApp(c *cli.Context) error {

	// cli arguments
	groupFilePath := c.String("file")
	// TODO: use the serverIdentityID / UUID + el.Search rather than the entry point index
	//entryPointIdx := c.Int("entryPointIdx")
	//proofs := c.Bool("proofs")

	// generate el with group file
	f, err := os.Open(groupFilePath)
	if err != nil {
		log.Error("Error while opening group file", err)
		return cli.NewExitError(err, 1)
	}
	el, err := app.ReadGroupToml(f)
	if err != nil {
		log.Error("Error while reading group file", err)
		return cli.NewExitError(err, 1)
	}
	if len(el.List) <= 0 {
		log.Error("Empty or invalid group file", err)
		return cli.NewExitError(err, 1)
	}

	/*err = unlynxAggRequest(os.Stdin, os.Stdout, el, entryPointIdx, proofs)
	if err != nil {
		log.Error("Error while querying Unlynx", err)
		return cli.NewExitError(err, 2)
	}*/

	return nil
}

// TODO: no log.Fatal in general (this stops immediately)
// TODO: handle errors in to/from bytes in crypto.go
// run aggregation of the results (and remaining protocols), all errors will be sent to the output
/*func unlynxAggRequest(input io.Reader, output io.Writer, el *onet.Roster, entryPointIdx int, proofs bool) error {
	start := time.Now()

	// get data from input
	xmlQuery, err := readAggRequestXMLFrom(input)
	if err != nil {
		log.Error("Error parsing AggRequest XML.", err)
		writeAggResponseXML(output, nil, nil, nil, err)
		return err
	}

	// get formatted data
	encQueryTerms, id, err := xmlQuery.AggRequestToUnlynxFormat()
	if err != nil {
		log.Error("Error extracing patients data.", err)
		writeAggResponseXML(output, nil, nil, nil, err)
		return err
	}

	parsingTime := time.Since(start)

	// launch query
	start = time.Now()

	client := serviceI2B2.NewUnLynxClient(el.List[entryPointIdx], strconv.Itoa(entryPointIdx))
	_, result, tr, err := client.SendSurveyAggRequestTerms(
		el, 					// Roster
		serviceI2B2.SurveyID(xmlQuery.QueryID), // SurveyID
		encQueryTerms, 				// Encrypted query terms to tag
		proofs,                                 // compute proofs?
	)

	totalTime := time.Since(start)

	if err != nil {
		log.Error("Error during the DDTRequest service.", err)
		writeAggResponseXML(output, nil, nil, nil, err)
		return err
	}

	// sanity check
	if len(result) == 0 || len(result) != len(encQueryTerms){
		log.Error("The number of tags",len(result), "does not match the number of terms",len(encQueryTerms), ".", err)
	}

	tr.DDTResquestTimeCommun = totalTime - tr.DDTRequestTimeExec
	tr.DDTparsingTime = parsingTime
	tr.DDTRequestTimeExec += tr.DDTparsingTime

	err = writeDDTResponseXML(output, xmlQuery, result, tr, nil)
	if err != nil {
		log.Error("Error while writing result.", err)
		writeDDTResponseXML(output, nil, nil, nil, err)
		return err
	}
	return nil
}*/
