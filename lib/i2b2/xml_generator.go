package lib_i2b2

import (
	"encoding/hex"
	"encoding/xml"
	"io"
	"io/ioutil"
	"math"
	"math/rand"
	"os"
	"strconv"

	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1/network"
	"github.com/JoaoAndreSa/MedCo/lib"
)

// Result contains one value
type Result struct {
	XMLName xml.Name `xml:"result"`
	Value   string   `xml:"value"`
}

// Column represents a column retrieved from database
type Column struct {
	XMLName   xml.Name `xml:"column"`
	Operation string   `xml:"operation"`
	Index     string   `xml:"index"`
	Values    []Result `xml:"result"`
}

// Data is the main structure of the xml file
type Data struct {
	XMLName         xml.Name `xml:"data"`
	SurveyID        string   `xml:"surveyid"`
	PublicKey       string   `xml:"publickey"`
	SecretKey       string   `xml:"secretkey"`
	NbrDataProvider string   `xml:"nbrdataproviders"`
	ExecutionMode   string   `xml:"mode"`
	Columns         []Column `xml:"column"`
}

// Medco is the root of xml file
type Medco struct {
	XMLName xml.Name `xml:"medco"`
	Results []Result `xml:"result"`
	Data    []Data   `xml:"data"`
}

// CreateXMLResult creates xml file containing a result
func CreateXMLResult(result string, filename string) {
	v := &Medco{}
	v.Results = append(v.Results, Result{Value: result})

	file, _ := os.Create(filename)

	xmlWriter := io.Writer(file)

	enc := xml.NewEncoder(xmlWriter)
	enc.Indent(" ", "    ")
	if err := enc.Encode(v); err != nil {
		log.Fatal(err)
	}
}

// ReadXMLResult reads xml file containing a result
func ReadXMLResult(fileName string) string {
	xmlFile, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer xmlFile.Close()

	XMLdata, _ := ioutil.ReadAll(xmlFile)
	var m Medco
	xml.Unmarshal(XMLdata, &m)

	log.LLvl1("Result read: ", m.Results[0].Value)
	return m.Results[0].Value
}

// CreateXMLData creates xml file containing data for an Unlynx query
func CreateXMLData(surveyID string, pubKey string, priKey string, nbrDataProviders string, mode string, columns [][]string, operations []string, filename string) {
	v := &Medco{}
	cols := make([]Column, len(columns))
	for i, v := range columns {
		for _, w := range v {
			if i == 0 {
				cols[i].Operation = ""
			} else {
				cols[i].Operation = operations[i-1]
			}
			cols[i].Values = append(cols[i].Values, Result{Value: w})

		}
	}
	v.Data = append(v.Data, Data{SurveyID: surveyID, PublicKey: pubKey, SecretKey: priKey, NbrDataProvider: nbrDataProviders, ExecutionMode: mode, Columns: cols})

	file, _ := os.Create(filename)

	xmlWriter := io.Writer(file)

	enc := xml.NewEncoder(xmlWriter)
	enc.Indent(" ", "    ")
	if err := enc.Encode(v); err != nil {
		log.Fatal(err)
	}
}

// ReadXMLData reads xml file containing data for an Unlynx query and generates the Unlynx query
func ReadXMLData(fileName string, collectiveKey abstract.Point) (surveyID lib.SurveyID, pubKey abstract.Point, secKey abstract.Scalar, querySubject, responses []lib.ClientResponse, executionMode, nbrDataProviders int64) {
	xmlFile, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer xmlFile.Close()
	XMLdata, _ := ioutil.ReadAll(xmlFile)
	var m Medco
	xml.Unmarshal(XMLdata, &m)

	surveyID = lib.SurveyID(m.Data[0].SurveyID)
	pubKeyB, err := hex.DecodeString(m.Data[0].PublicKey)
	pubKey = network.Suite.Point()
	pubKey.UnmarshalBinary(pubKeyB)
	secKey = network.Suite.Scalar()
	secKeyB, err := hex.DecodeString(m.Data[0].SecretKey)
	secKey.UnmarshalBinary(secKeyB)

	executionMode, _ = strconv.ParseInt(m.Data[0].ExecutionMode, 10, 32)
	nbrDataProviders, _ = strconv.ParseInt(m.Data[0].NbrDataProvider, 10, 32)

	operations := make([]string, 0)
	responsesStr := make([]lib.ClientResponse, len(m.Data[0].Columns[0].Values))
	responsesStrFin := make([]lib.ClientResponse, 0)

	for j, v := range m.Data[0].Columns {
		// query predicate
		if v.Operation != "" {
			operations = append(operations, v.Operation)
		}

		// query responses
		for q, w := range v.Values {
			valRead, _ := hex.DecodeString(w.Value)
			ct := lib.CipherText{}
			ct.FromBytes(valRead)
			if j == 0 {
				responsesStr[q] = lib.NewClientResponse(0, 1)
				responsesStr[q].AggregatingAttributes = lib.CipherVector{*lib.EncryptInt(collectiveKey, int64(1))}
			}
			responsesStr[q].ProbaGroupingAttributesEnc = append(responsesStr[q].ProbaGroupingAttributesEnc, ct)

			if j == len(m.Data[0].Columns)-1 {
				responsesStrFin = append(responsesStrFin, responsesStr[q])
			}
		}
	}
	// query subject creation and dummies creation
	res := querySubjectSelectClear(operations, createClearQuerySubject(operations))
	querySubject, dummies := querySubjectEncryption(collectiveKey, res)

	//TODO dummies should be randomly added in the responses and not at the end
	responses = append(responsesStrFin, dummies...)
	return surveyID, pubKey, secKey, querySubject, responses, executionMode, nbrDataProviders
}

// createClearQuerySubject generates all the combinations of 0,1
func createClearQuerySubject(operations []string) [][]int64 {
	if operations != nil {
		querySubject := make([][]int64, len(operations)+1)
		repetitions := int(math.Pow(2, float64(len(operations)+1)))
		for i := 0; i < len(operations)+1; i++ {
			count := 0
			repetitions = repetitions / 2
			for j := 0; j < int(math.Pow(2, float64(len(operations)+1))); j++ {
				if j == 0 {
					querySubject[i] = make([]int64, int(math.Pow(2, float64(len(operations)+1))))
				}
				if count < repetitions {
					querySubject[i][j] = 0
					count++
				} else {
					querySubject[i][j] = 1
					count++
					if count == 2*repetitions {
						count = 0
					}
				}

			}
		}
		querySubjectForm := make([][]int64, len(querySubject[0]))
		for i := range querySubject[0] {
			querySubjectForm[i] = make([]int64, len(querySubject))
			for j := range querySubjectForm[i] {
				querySubjectForm[i][j] = querySubject[j][i]
			}
		}
		return querySubjectForm
	}
	return [][]int64{[]int64{int64(1)}}
}

// querySubjectSelectClear filters the 0,1 combinations to keep only ones satisfying the query
func querySubjectSelectClear(operations []string, subject [][]int64) [][]int64 {
	result := make([][]int64, 0)
	for _, v := range subject {
		tmpsRes := make([]int64, 0)
		count := 0
		for j, w := range v {
			if j == 0 {
				tmpsRes = append(tmpsRes, 0)
				tmpsRes[count] = w
			} else {
				if operations[j-1] == "OR" {
					tmpsRes[count] = tmpsRes[count] + w
				} else if operations[j-1] == "AND" {
					count++
					tmpsRes = append(tmpsRes, 0)
					tmpsRes[count] = tmpsRes[count] + w
				}
			}

		}
		present := false
		for _, q := range tmpsRes {
			if q == 0 {
				present = true
			}
		}
		if !present {
			result = append(result, v)
		}

	}
	return result
}

// querySubjectEncryption permits to encrypt the query subject and create dummies
func querySubjectEncryption(collKey abstract.Point, subject [][]int64) (qs, dummies []lib.ClientResponse) {
	encryptedSubject := make([]lib.ClientResponse, 0)
	dummies = make([]lib.ClientResponse, 0)
	for _, v := range subject {
		tmp := lib.ClientResponse{}
		tmp.ProbaGroupingAttributesEnc = *lib.EncryptIntVector(collKey, v)
		tmp.AggregatingAttributes = *lib.EncryptIntVector(collKey, []int64{0})
		encryptedSubject = append(encryptedSubject, tmp)
		rand.Seed(int64(len(subject)))
		rnd := rand.Int63n(2) * rand.Int63n(6)
		for i := int64(0); i < rnd; i++ {
			tmp := lib.ClientResponse{}
			tmp.ProbaGroupingAttributesEnc = *lib.EncryptIntVector(collKey, v)
			tmp.AggregatingAttributes = *lib.EncryptIntVector(collKey, []int64{0})
			dummies = append(dummies, tmp)
		}
	}
	log.LLvl1("Added ", len(dummies), " dummy response")
	qs = encryptedSubject
	return qs, dummies
}
