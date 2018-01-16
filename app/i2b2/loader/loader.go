package loader

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/services/i2b2"
	"gopkg.in/dedis/crypto.v0/base64"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// DBSettings stores the database settings
type DBSettings struct {
	DBhost     string
	DBport     int
	DBuser     string
	DBpassword string
	DBname     string
}

// The different paths and handlers for all the .sql files
var (
	Tablenames = [...]string{"shrine_ont.clinical_sensitive",
		"shrine_ont.clinical_non_sensitive",
		"genomic_annotations.genomic_annotations",
		"i2b2metadata.sensitive_tagged",
		"i2b2metadata.non_sensitive_clear",
		"i2b2demodata.concept_dimension",
		"i2b2demodata.patient_mapping",
		"i2b2demodata.patient_dimension",
		"i2b2demodata.encounter_mapping",
		"i2b2demodata.visit_dimension",
		"i2b2demodata.provider_dimension",
		"i2b2demodata.observation_fact"}

	FileBashPath = "26-load-data.sh"

	FilePaths = [...]string{"files/SHRINE_ONT_CLINICAL_SENSITIVE.csv",
		"files/SHRINE_ONT_CLINICAL_NON_SENSITIVE.csv",
		"files/SHRINE_ONT_GENOMIC_ANNOTATIONS.csv",
		"files/I2B2METADATA_SENSITIVE_TAGGED.csv",
		"files/I2B2METADATA_NON_SENSITIVE_CLEAR.csv",
		"files/I2B2DEMODATA_CONCEPT_DIMENSION.csv",
		"files/I2B2DEMODATA_PATIENT_MAPPING.csv",
		"files/I2B2DEMODATA_PATIENT_DIMENSION.csv",
		"files/I2B2DEMODATA_ENCOUNTER_MAPPING.csv",
		"files/I2B2DEMODATA_VISIT_DIMENSION.csv",
		"files/I2B2DEMODATA_PROVIDER_DIMENSION.csv",
		"files/I2B2DEMODATA_OBSERVATION_FACT.csv"}
)

// PatientVisitLink contains the link between the patient and the visit/encounter (patient ID and sample ID)
type PatientVisitLink struct {
	PatientID   int64
	EncounterID int64
}

// ConceptPath defines the end of the concept path tree and we use it in a map so that we do not repeat concepts
type ConceptPath struct {
	Field  string
	Record string //leaf
}

// ConceptID defines its ID (e.g., E,1 - for ENC_ID,1; C,1 - for CLEAR_ID,1; sdasdcfsx,1432 - for tagged_value,TAG_ID
type ConceptID struct {
	Identifier string
	Value      int64
}

// Support global variables
var (
	Testing         bool // testing environment
	FileHandlers    []*os.File
	OntValues       map[ConceptPath]ConceptID // stores the concepth path and the correspondent ID
	TextSearchIndex int64                     // needed for the observation_fact table (counter)
)

// ReplayDataset replays the dataset x number of times
func ReplayDataset(filename string, x int) error {
	log.LLvl1("Replaying dataset", x, "times...")

	// open file to read
	fGenomic, err := os.Open(filename)
	if err != nil {
		log.Fatal("Cannot open file to read:", err)
		return err
	}

	reader := csv.NewReader(fGenomic)
	reader.Comma = '\t'

	// read all genomic file
	record, err := reader.ReadAll()
	if err != nil {
		log.Fatal("Error in the ReplayDataset() - reading:", err)
		return err
	}

	finalResult := record[:]

	header := true
	// replay x times
	for t := 0; t < x-1; t++ {
		for _, el := range record {
			// not a comment or blank line
			if string(el[0]) == "" || string(el[0][0:1]) == "#" {
				continue
			}

			// HEADER time...
			if header == true {
				header = false
				continue
			}

			finalResult = append(finalResult, el)
		}
	}

	fGenomic.Close()

	// open file to write
	fGenomic, err = os.Create(filename)
	if err != nil {
		log.Fatal("Cannot open file to write:", err)
		return err
	}

	writer := csv.NewWriter(fGenomic)
	writer.Comma = '\t'

	err = writer.WriteAll(finalResult)
	if err != nil {
		log.Fatal("Error in the ReplayDataset() - writing:", err)
		return err
	}

	fGenomic.Close()

	return nil

}

// LoadClient initiates the loading process
func LoadClient(el *onet.Roster, entryPointIdx int, fOntClinical, fOntGenomic, fClinical, fGenomic *os.File, listSensitive []string, databaseS DBSettings, testing bool) error {
	start := time.Now()

	// init global variables
	FileHandlers = make([]*os.File, 0)
	OntValues = make(map[ConceptPath]ConceptID)
	Testing = testing
	TextSearchIndex = int64(1) // needed for the observation_fact table (counter)

	for _, f := range FilePaths {
		fp, err := os.Create(f)
		if err != nil {
			log.Fatal("Error while opening", f)
			return err
		}
		FileHandlers = append(FileHandlers, fp)
	}

	err := GenerateOntologyFiles(el, entryPointIdx, fOntClinical, fOntGenomic, listSensitive)
	if err != nil {
		log.Fatal("Error while generating the ontology .csv files", err)
		return err
	}

	// to free

	err = GenerateDataFiles(el, fClinical, fGenomic)
	if err != nil {
		log.Fatal("Error while generating the data .csv files", err)
		return err
	}

	fClinical.Close()
	fGenomic.Close()

	err = GenerateLoadingScript(databaseS)
	if err != nil {
		log.Fatal("Error while generating the loading .sh file", err)
		return err
	}

	fOntClinical.Close()
	fOntGenomic.Close()

	err = LoadDataFiles()
	if err != nil {
		log.Fatal("Error while loading .sql file", err)
		return err
	}

	for _, fp := range FileHandlers {
		fp.Close()
	}

	// to free memory
	OntValues = make(map[ConceptPath]ConceptID)
	FileHandlers = make([]*os.File, 0)

	loadTime := time.Since(start)

	log.LLvl1("The loading took:", loadTime)

	return nil
}

// GenerateLoadingScript creates a load .sql script
func GenerateLoadingScript(databaseS DBSettings) error {
	fp, err := os.Create(FileBashPath)
	if err != nil {
		return err
	}

	loading := `#!/usr/bin/env bash` + "\n" + "\n" + `PGPASSWORD=` + databaseS.DBpassword + ` psql -v ON_ERROR_STOP=1 -h "` + databaseS.DBhost +
		`" -U "` + databaseS.DBuser + `" -p ` + strconv.FormatInt(int64(databaseS.DBport), 10) + ` -d "` + databaseS.DBname + `" <<-EOSQL` + "\n"

	loading += "BEGIN;\n"
	for i := 0; i < len(Tablenames); i++ {
		tokens := strings.Split(FilePaths[i], "/")

		loading += `\copy ` + Tablenames[i] + ` FROM 'files/` + tokens[1] + `' ESCAPE '"' DELIMITER ',' CSV;` + "\n"
	}
	loading += "COMMIT;\n"
	loading += "EOSQL"

	_, err = fp.WriteString(loading)
	if err != nil {
		return err
	}

	fp.Close()
	return nil
}

// LoadDataFiles executes the loading script
func LoadDataFiles() error {
	// Display just the stderr if an error occurs
	cmd := exec.Command("/bin/sh", FileBashPath)
	stderr := &bytes.Buffer{} // make sure to import bytes
	cmd.Stderr = stderr
	err := cmd.Run()
	if err != nil {
		log.LLvl1("Error when running command.  Error log:", stderr.String())
		log.LLvl1("Got command status:", err.Error())
		return err
	}

	return nil
}

// GenerateOntologyFiles generates the .csv files that 'belong' to the whole ontology (metadata & shrine)
func GenerateOntologyFiles(group *onet.Roster, entryPointIdx int, fOntClinical, fOntGenomic *os.File, listSensitive []string) error {

	keyForSensitiveIDs := make([]ConceptPath, 0) // stores the concept path for the corresponding EncID(s) and the genomic IDs
	allSensitiveIDs := make([]int64, 0)          // stores the EncID(s) and the genomic IDs

	encID := int64(1)   // clinical sensitive IDs
	clearID := int64(1) // clinical non-sensitive IDs

	// load clinical ontology
	reader := csv.NewReader(fOntClinical)
	reader.Comma = '\t'

	first := true
	headerClinical := make([]string, 0)
	for {
		// read just one record, but we could ReadAll() as well
		record, err := reader.Read()
		// end-of-file is fitted into err
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		// if it is not a commented line
		if len(record) > 0 && string(record[0]) != "" && string(record[0][0:1]) != "#" {
			// the HEADER
			if first == true {

				// skip SampleID and PatientID
				for i := 2; i < len(record); i++ {

					// sensitive
					if containsArrayString(listSensitive, record[i]) == true || (len(listSensitive) == 1 && listSensitive[0] == "all") {
						if err := writeShrineOntologyEnc(record[i]); err != nil {
							return err
						}
						// we don't generate the MetadataOntologyEnc because we will do this afterwards (so that we only perform 1 DDT with all sensitive elements)
					} else {
						if err := writeShrineOntologyClear(record[i]); err != nil {
							return err
						}
						if err := writeMetadataOntologyClear(record[i]); err != nil {
							return err
						}
					}
					headerClinical = append(headerClinical, record[i])

				}
				first = false

			} else {

				for i, j := 2, 0; i < len(record); i, j = i+1, j+1 {

					if record[i] == "" {
						record[i] = "<empty>"
					}

					// sensitive
					if containsArrayString(listSensitive, headerClinical[j]) == true || (len(listSensitive) == 1 && listSensitive[0] == "all") {
						// if concept path does not exist
						if _, ok := OntValues[ConceptPath{Field: headerClinical[j], Record: record[i]}]; ok == false {
							if err := writeShrineOntologyLeafEnc(headerClinical[j], record[i], encID); err != nil {
								return err
							}
							// we don't generate the MetadataOntologyLeafEnc because we will do this afterwards (so that we only perform 1 DDT with all sensitive elements)

							keyForSensitiveIDs = append(keyForSensitiveIDs, ConceptPath{Field: headerClinical[j], Record: record[i]})
							allSensitiveIDs = append(allSensitiveIDs, encID)
							OntValues[ConceptPath{Field: headerClinical[j], Record: record[i]}] = ConceptID{Identifier: "E", Value: encID}
							encID++
						}

					} else {
						// if concept path does not exist
						if _, ok := OntValues[ConceptPath{Field: headerClinical[j], Record: record[i]}]; ok == false {
							if err := writeShrineOntologyLeafClear(headerClinical[j], record[i], clearID); err != nil {
								return err
							}
							if err := writeMetadataOntologyLeafClear(headerClinical[j], record[i], clearID); err != nil {
								return err
							}

							OntValues[ConceptPath{Field: headerClinical[j], Record: record[i]}] = ConceptID{Identifier: "C", Value: clearID}
							clearID++
						}

					}

				}

			}
		}
	}

	fOntClinical.Close()

	log.LLvl1("Finished parsing the clinical ontology...")

	// load genomic
	reader = csv.NewReader(fOntGenomic)
	reader.Comma = '\t'

	first = true
	headerGenomic := make([]string, 0)
	// this arrays stores the indexes of the fields we need to use to generate a genomic id
	indexGenVariant := make(map[string]int)
	for {
		// read just one record, but we could ReadAll() as well
		record, err := reader.Read()
		// end-of-file is fitted into err
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		// if it is not a commented line
		if len(record) > 0 && string(record[0]) != "" && string(record[0][0:1]) != "#" {

			// the HEADER
			if first == true {
				for i, el := range record {
					if el == "Tumor_Sample_Barcode" || el == "Chromosome" || el == "Start_Position" || el == "Reference_Allele" || el == "Tumor_Seq_Allele1" {
						indexGenVariant[el] = i
					}
					headerGenomic = append(headerGenomic, el)

				}
				first = false
			} else {
				genomicID, err := generateGenomicID(indexGenVariant, record)

				// if genomic id already exist we don't need to add it to the shrine_ont.genomic_annotations
				if err == nil && containsArrayInt64(allSensitiveIDs, genomicID) == false {
					if err := writeShrineOntologyGenomicAnnotations(genomicID, headerGenomic, indexGenVariant, record); err != nil {
						return err
					}

					keyForSensitiveIDs = append(keyForSensitiveIDs, ConceptPath{Field: strconv.FormatInt(genomicID, 10), Record: ""})
					allSensitiveIDs = append(allSensitiveIDs, genomicID)
				}
			}

		}

	}

	fOntGenomic.Close()

	log.LLvl1("Finished parsing the genomic ontology...")

	// write the tagged values

	taggedValues, err := EncryptAndTag(allSensitiveIDs, group, entryPointIdx)
	if err != nil {
		return err
	}

	return writeMetadataSensitiveTagged(taggedValues, keyForSensitiveIDs)
}

// GenerateDataFiles generates the .csv files that 'belong' to the dataset (demodata)
func GenerateDataFiles(group *onet.Roster, fClinical, fGenomic *os.File) error {
	// patient_id counter
	pid := int64(1)
	// encounter_id counter
	eid := int64(1)

	ontValuesSmallCopy := make(map[ConceptPath]bool)     // reduced set of ontology data to ensure that no repeated elements are added to the concept dimension table
	patientVisitMap := make(map[string]PatientVisitLink) // maps between the Sample ID (Tumor_barcode) and a combination of patient and encounter IDs
	visitMapping := make(map[string]int64)               // map a sample ID to a numeric ID
	patientMapping := make(map[string]int64)             // map a patient ID to a numeric ID

	if err := writeDemodataProviderDimension(); err != nil {
		return err
	}

	// load clinical
	reader := csv.NewReader(fClinical)
	reader.Comma = '\t'

	first := true
	headerClinical := make([]string, 0)
	for {
		// read just one record, but we could ReadAll() as well
		record, err := reader.Read()
		// end-of-file is fitted into err
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		// if it is not a commented line
		if len(record) > 0 && string(record[0]) != "" && string(record[0][0:1]) != "#" {

			// the HEADER
			if first == true {

				// skip SampleID and PatientID
				for i := 2; i < len(record); i++ {
					headerClinical = append(headerClinical, record[i])

				}
				first = false
			} else {
				// patient not yet exists
				if _, ok := patientMapping[record[1]]; ok == false {

					patientMapping[record[1]] = pid

					if err := writeDemodataPatientMapping(record[1], patientMapping[record[1]]); err != nil {
						return err
					}
					if err := writeDemodataPatientDimension(group, patientMapping[record[1]]); err != nil {
						return err
					}

					pid++
				}

				visitMapping[record[0]] = eid

				if err := writeDemodataEncounterMapping(record[0], record[1], visitMapping[record[0]]); err != nil {
					return err
				}
				if err := writeDemodataVisitDimension(visitMapping[record[0]], patientMapping[record[1]]); err != nil {
					return err
				}

				eid++

				patientVisitMap[record[0]] = PatientVisitLink{PatientID: patientMapping[record[1]], EncounterID: visitMapping[record[0]]}

				for i, j := 2, 0; i < len(record); i, j = i+1, j+1 {

					if record[i] == "" {
						record[i] = "<empty>"
					}

					// check if it exists in the ontology
					if _, ok := OntValues[ConceptPath{Field: headerClinical[j], Record: record[i]}]; ok == true {
						// sensitive
						if OntValues[ConceptPath{Field: headerClinical[j], Record: record[i]}].Identifier != "C" {
							// if concept path does not exist
							if _, ok := ontValuesSmallCopy[ConceptPath{Field: headerClinical[j], Record: record[i]}]; ok == false {
								if err := writeDemodataConceptDimensionTaggedConcepts(headerClinical[j], record[i]); err != nil {
									return err
								}
								ontValuesSmallCopy[ConceptPath{Field: headerClinical[j], Record: record[i]}] = true
							}

							if err := writeDemodataObservationFactEnc(OntValues[ConceptPath{Field: headerClinical[j], Record: record[i]}].Value,
								patientMapping[record[1]],
								visitMapping[record[0]]); err != nil {
								return err
							}

						} else {
							// if concept path does not exist
							if _, ok := ontValuesSmallCopy[ConceptPath{Field: headerClinical[j], Record: record[i]}]; ok == false {
								if err := writeDemodataConceptDimensionCleartextConcepts(headerClinical[j], record[i]); err != nil {
									return err
								}
								ontValuesSmallCopy[ConceptPath{Field: headerClinical[j], Record: record[i]}] = true
							}

							if err := writeDemodataObservationFactClear(OntValues[ConceptPath{Field: headerClinical[j], Record: record[i]}].Value,
								patientMapping[record[1]],
								visitMapping[record[0]]); err != nil {
								return err
							}
						}
					} else {
						log.Fatal("There are elements in the dataset that do not belong to the existing ontology")
						return err
					}
				}

			}
		}
	}

	fClinical.Close()

	log.LLvl1("Finished parsing the clinical dataset...")

	// load genomic
	reader = csv.NewReader(fGenomic)
	reader.Comma = '\t'

	first = true
	headerGenomic := make([]string, 0)
	// this arrays stores the indexes of the fields we need to use to generate a genomic id
	indexGenVariant := make(map[string]int)
	for {
		// read just one record, but we could ReadAll() as well
		record, err := reader.Read()

		// end-of-file is fitted into err
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		// if it is not a commented line
		if len(record) > 0 && string(record[0]) != "" && string(record[0][0:1]) != "#" {

			// the HEADER
			if first == true {
				for i, el := range record {
					if el == "Tumor_Sample_Barcode" || el == "Chromosome" || el == "Start_Position" || el == "Reference_Allele" || el == "Tumor_Seq_Allele1" {
						indexGenVariant[el] = i
					}
					headerGenomic = append(headerGenomic, el)

				}
				first = false
			} else {
				genomicID, err := generateGenomicID(indexGenVariant, record)

				if err == nil {

					// check if it exists in the ontology
					if _, ok := OntValues[ConceptPath{Field: strconv.FormatInt(genomicID, 10), Record: ""}]; ok == true {
						// if concept path does not exist
						if _, ok := ontValuesSmallCopy[ConceptPath{Field: strconv.FormatInt(genomicID, 10), Record: ""}]; ok == false {
							if err := writeDemodataConceptDimensionTaggedConcepts(strconv.FormatInt(genomicID, 10), ""); err != nil {
								return err
							}
							ontValuesSmallCopy[ConceptPath{Field: strconv.FormatInt(genomicID, 10), Record: ""}] = true
						}

						if err := writeDemodataObservationFactEnc(OntValues[ConceptPath{Field: strconv.FormatInt(genomicID, 10), Record: ""}].Value,
							patientVisitMap[record[indexGenVariant["Tumor_Sample_Barcode"]]].PatientID,
							patientVisitMap[record[indexGenVariant["Tumor_Sample_Barcode"]]].EncounterID); err != nil {
							return err
						}
					} else {
						log.Fatal("There are elements in the dataset that do not belong to the existing ontology")
						return err
					}
				}
			}

		}
	}

	fGenomic.Close()

	log.LLvl1("Finished parsing the genomic dataset...")

	log.LLvl1("The End.")

	return nil
}

func writeShrineOntologyEnc(el string) error {

	/*clinicalSensitive := `INSERT INTO shrine_ont.clinical_sensitive VALUES (3, '\medco\clinical\sensitive\` + el + `\', '` + el + `', 'N', 'CA', NULL, NULL, NULL, 'concept_cd', 'concept_dimension', 'concept_path', 'T', 'LIKE',
	  '\medco\clinical\sensitive\` + el + `\', 'Sensitive field encrypted by Unlynx', '\medco\clinical\sensitive\` + el + `\',
	   'NOW()', NULL, NULL, NULL, 'ENC_ID', '@', NULL, NULL, NULL, NULL);` + "\n"*/

	clinicalSensitive := `"3","\medco\clinical\sensitive\` + el + `\","` + el + `","N","CA",,,,"concept_cd","concept_dimension","concept_path","T","LIKE","\medco\clinical\sensitive\` + el + `\","Sensitive field encrypted by Unlynx","\medco\clinical\sensitive\` + el + `\","NOW()",,,,"ENC_ID","@",,,,` + "\n"

	_, err := FileHandlers[0].WriteString(clinicalSensitive)

	if err != nil {
		log.Fatal("Error in the writeShrineOntologyEnc():", err)
		return err
	}

	return nil
}

func writeShrineOntologyLeafEnc(field, el string, id int64) error {

	/*clinicalSensitive := `INSERT INTO shrine_ont.clinical_sensitive VALUES (4, '\medco\clinical\sensitive\` + field + `\` + el + `\', '` + el + `', 'N', 'LA', NULL, 'ENC_ID:` + strconv.FormatInt(id, 10) + `', NULL, 'concept_cd', 'concept_dimension', 'concept_path', 'T', 'LIKE',
	  '\medco\clinical\sensitive\` + field + `\` + el + `\', 'Sensitive value encrypted by Unlynx',  '\medco\clinical\sensitive\` + field + `\` + el + `\',
	   'NOW()', NULL, NULL, NULL, 'ENC_ID', '@', NULL, NULL, NULL, NULL);` + "\n"*/

	clinicalSensitive := `"4","\medco\clinical\sensitive\` + field + `\` + el + `\","` + el + `","N","LA",,"ENC_ID:` + strconv.FormatInt(id, 10) + `",,"concept_cd","concept_dimension","concept_path","T","LIKE","\medco\clinical\sensitive\` + field + `\` + el + `\","Sensitive value encrypted by Unlynx","\medco\clinical\sensitive\` + field + `\` + el + `\","NOW()",,,,"ENC_ID","@",,,,` + "\n"

	_, err := FileHandlers[0].WriteString(clinicalSensitive)

	if err != nil {
		log.Fatal("Error in the writeShrineOntologyLeafEnc():", err)
		return err
	}

	return nil
}

func writeShrineOntologyClear(el string) error {

	/*clinical := `INSERT INTO shrine_ont.clinical_non_sensitive VALUES (3, '\medco\clinical\nonsensitive\` + el + `\', '` + el + `', 'N', 'CA', NULL, NULL, NULL, 'concept_cd', 'concept_dimension', 'concept_path', 'T', 'LIKE',
	  '\medco\clinical\nonsensitive\` + el + `\', 'Non-sensitive field', '\medco\clinical\nonsensitive\` + el + `\',
	   'NOW()', NULL, NULL, NULL, 'CLEAR', '@', NULL, NULL, NULL, NULL);` + "\n"*/

	clinical := `"3","\medco\clinical\nonsensitive\` + el + `\","` + el + `","N","CA",,,,"concept_cd","concept_dimension","concept_path","T","LIKE","\medco\clinical\nonsensitive\` + el + `\","Non-sensitive field","\medco\clinical\nonsensitive\` + el + `\","NOW()",,,,"CLEAR","@",,,,` + "\n"

	_, err := FileHandlers[1].WriteString(clinical)

	if err != nil {
		log.Fatal("Error in the writeShrineOntologyClear():", err)
		return err
	}

	return nil
}

func writeShrineOntologyLeafClear(field, el string, id int64) error {

	/*clinical := `INSERT INTO shrine_ont.clinical_non_sensitive VALUES (4, '\medco\clinical\nonsensitive\` + field + `\` + el + `\', '` + el + `', 'N', 'LA', NULL, 'CLEAR:` + strconv.FormatInt(id, 10) + `', NULL, 'concept_cd', 'concept_dimension', 'concept_path', 'T', 'LIKE',
	  '\medco\clinical\nonsensitive\` + field + `\` + el + `\', 'Non-sensitive value',  '\medco\clinical\sensitive\` + field + `\` + el + `\',
	   'NOW()', NULL, NULL, NULL, 'CLEAR', '@', NULL, NULL, NULL, NULL);` + "\n"*/

	clinical := `"4","\medco\clinical\nonsensitive\` + field + `\` + el + `\","` + el + `","N","LA",,"CLEAR:` + strconv.FormatInt(id, 10) + `",,"concept_cd","concept_dimension","concept_path","T","LIKE","\medco\clinical\nonsensitive\` + field + `\` + el + `\","Non-sensitive value","\medco\clinical\sensitive\` + field + `\` + el + `\","NOW()",,,,"CLEAR","@",,,,` + "\n"

	_, err := FileHandlers[1].WriteString(clinical)

	if err != nil {
		log.Fatal("Error in the writeShrineOntologyLeafClear():", err)
		return err
	}

	return nil
}

func generateGenomicID(indexGenVariant map[string]int, record []string) (int64, error) {

	// if the ref and alt are too big ignore them (for now....)
	if len(record[indexGenVariant["Reference_Allele"]]) > 6 || len(record[indexGenVariant["Tumor_Seq_Allele1"]]) > 6 {
		return int64(-1), errors.New("Reference and/or Alternate base size is bigger than the maximum allowed")
	}

	// generate id
	aux, err := strconv.ParseInt(record[indexGenVariant["Start_Position"]], 10, 64)
	if err != nil {
		return int64(-1), err
	}

	id, err := GetVariantID(record[indexGenVariant["Chromosome"]], aux, record[indexGenVariant["Reference_Allele"]], record[indexGenVariant["Tumor_Seq_Allele1"]])
	if err != nil {
		return int64(-1), err
	}

	return id, nil

}

func writeShrineOntologyGenomicAnnotations(id int64, fields []string, indexGenVariant map[string]int, record []string) error {

	otherFields := ""
	for i, el := range record {
		if _, ok := indexGenVariant[el]; ok == false {
			//otherFields += fields[i] + ":" + strings.Replace(el, "'", "''", -1) + ", "

			otherFields += "\"\"" + fields[i] + "\"\":\"\"" + el + "\"\", "
		}
	}
	// remove the last ", "
	otherFields = otherFields[:len(otherFields)-2]

	/*annotation := `INSERT INTO shrine_ont.genomic_annotations VALUES ('` + strconv.FormatInt(id, 10) + `', '{ ` + otherFields + `}');` + "\n"*/

	annotation := `"` + strconv.FormatInt(id, 10) + `","{` + otherFields + `}"` + "\n"

	_, err := FileHandlers[2].WriteString(annotation)

	if err != nil {
		log.Fatal("Error in the writeShrineOntologyGenomicAnnotations():", err)
		return err
	}

	return nil
}

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

// EncryptAndTag encrypts the query elements and tags them to allow for the comparison between elements
func EncryptAndTag(list []int64, group *onet.Roster, entryPointIdx int) ([]lib.GroupingKey, error) {

	// ENCRYPTION
	start := time.Now()
	listEncryptedElements := make(lib.CipherVector, len(list))

	for i := int64(0); i < int64(len(list)); i++ {
		listEncryptedElements[i] = *lib.EncryptInt(group.Aggregate, list[i])
	}
	log.LLvl1("Finished encrypting the sensitive data... (", time.Since(start), ")")

	// TAGGING
	start = time.Now()
	client := serviceI2B2.NewUnLynxClient(group.List[entryPointIdx], strconv.Itoa(entryPointIdx))
	_, result, tr, err := client.SendSurveyDDTRequestTerms(
		group, // Roster
		serviceI2B2.SurveyID("tagging_loading_phase"), // SurveyID
		listEncryptedElements,                         // Encrypted query terms to tag
		false, // compute proofs?
		Testing,
	)

	if err != nil {
		log.Fatal("Error during DDT")
		return nil, err
	}

	totalTime := time.Since(start)

	tr.DDTRequestTimeCommun = totalTime - tr.DDTRequestTimeExec

	log.LLvl1("DDT took: exec -", tr.DDTRequestTimeExec, "commun -", tr.DDTRequestTimeCommun)

	log.LLvl1("Finished tagging the sensitive data... (", totalTime, ")")

	return result, nil
}

func writeMetadataSensitiveTagged(list []lib.GroupingKey, keyForSensitiveIDs []ConceptPath) error {

	if len(list) != len(keyForSensitiveIDs) {
		log.Fatal("The number of sensitive elements does not match the number of 'KeyForSensitiveID's.")
		return errors.New("")
	}

	tagIDs := make(map[int64]bool)

	for i, el := range list {
		// generate a tagID with 32bits (cannot be repeated)
		ok := false
		var tagID uint32

		// while random tag is not unique
		for ok == false {
			b, err := GenerateRandomBytes(4)

			if err != nil {
				log.Fatal("Error while generating random number", err)
				return err
			}

			tagID = binary.BigEndian.Uint32(b)

			// if random tag does not exist yet
			if _, okTagID := tagIDs[int64(tagID)]; okTagID == false {
				tagIDs[int64(tagID)] = true
				ok = true
			}
		}

		/*sensitive := `INSERT INTO i2b2metadata.sensitive_tagged VALUES (2, '\medco\tagged\` + string(el) + `\', '', 'N', 'LA ', NULL, 'TAG_ID:` + strconv.FormatUint(int64(tagID), 10) + `', NULL, 'concept_cd', 'concept_dimension', 'concept_path', 'T', 'LIKE',
		'\medco\tagged\` + string(el) + `\', NULL, NULL, 'NOW()', NULL, NULL, NULL, 'TAG_ID', '@', NULL, NULL, NULL, NULL);` + "\n"*/

		sensitive := `"2","\medco\tagged\` + string(el) + `\","""","N","LA",,"TAG_ID:` + strconv.FormatInt(int64(tagID), 10) + `",,"concept_cd","concept_dimension","concept_path","T","LIKE","\medco\tagged\` + string(el) + `\",,,"NOW()",,,,"TAG_ID","@",,,,` + "\n"

		_, err := FileHandlers[3].WriteString(sensitive)

		if err != nil {
			log.Fatal("Error in the writeMetadataSensitiveTagged():", err)
			return err
		}

		OntValues[keyForSensitiveIDs[i]] = ConceptID{Identifier: string(el), Value: int64(tagID)}
	}
	return nil
}

func writeMetadataOntologyClear(el string) error {

	/*clinical := `INSERT INTO i2b2metadata.clinical_non_sensitive VALUES (3, '\medco\clinical\nonsensitive\` + el + `\', '` + el + `', 'N', 'CA', NULL, NULL, NULL, 'concept_cd', 'concept_dimension', 'concept_path', 'T', 'LIKE',
	  '\medco\clinical\nonsensitive\` + el + `\', 'Non-sensitive field', '\medco\clinical\nonsensitive\` + el + `\',
	   'NOW()', NULL, NULL, NULL, 'CLEAR', '@', NULL, NULL, NULL, NULL);` + "\n"*/

	clinical := `"3","\medco\clinical\nonsensitive\` + el + `\","` + el + `","N","CA",,,,"concept_cd","concept_dimension","concept_path","T","LIKE","\medco\clinical\nonsensitive\` + el + `\","Non-sensitive field","\medco\clinical\nonsensitive\` + el + `\","NOW()",,,,"CLEAR","@",,,,` + "\n"

	_, err := FileHandlers[4].WriteString(clinical)

	if err != nil {
		log.Fatal("Error in the writeMetadataOntologyClear():", err)
		return err
	}

	return nil
}

func writeMetadataOntologyLeafClear(field, el string, id int64) error {

	/*clinical := `INSERT INTO i2b2metadata.clinical_non_sensitive VALUES (4, '\medco\clinical\nonsensitive\` + field + `\` + el + `\', '` + el + `', 'N', 'LA', NULL, 'CLEAR:` + strconv.FormatInt(id, 10) + `', NULL, 'concept_cd', 'concept_dimension', 'concept_path', 'T', 'LIKE',
	  '\medco\clinical\nonsensitive\` + field + `\` + el + `\', 'Non-sensitive value',  '\medco\clinical\sensitive\` + field + `\` + el + `\',
	   'NOW()', NULL, NULL, NULL, 'CLEAR', '@', NULL, NULL, NULL, NULL);` + "\n"*/

	clinical := `"4","\medco\clinical\nonsensitive\` + field + `\` + el + `\","` + el + `","N","LA",,"CLEAR:` + strconv.FormatInt(id, 10) + `",,"concept_cd","concept_dimension","concept_path","T","LIKE","\medco\clinical\nonsensitive\` + field + `\` + el + `\","Non-sensitive value","\medco\clinical\sensitive\` + field + `\` + el + `\","NOW()",,,,"CLEAR","@",,,,` + "\n"

	_, err := FileHandlers[4].WriteString(clinical)

	if err != nil {
		log.Fatal("Error in the writeMetadataOntologyLeafClear():", err)
		return err
	}

	return nil
}

func writeDemodataConceptDimensionCleartextConcepts(field, el string) error {

	/*cleartextConcepts := `INSERT INTO i2b2demodata.concept_dimension VALUES ('\medco\clinical\nonsensitive\` + field + `\` + record + `\', 'CLEAR:` + strconv.FormatInt(OntValues[ConceptPath{Field: field, Record: record}].Value, 10) + `', '` + record + `', NULL, NULL, NULL, 'NOW()', NULL, NULL);` + "\n"*/

	cleartextConcepts := `"\medco\clinical\nonsensitive\` + field + `\` + el + `\","CLEAR:` + strconv.FormatInt(OntValues[ConceptPath{Field: field, Record: el}].Value, 10) + `","` + el + `",,,,"NOW()",,` + "\n"

	_, err := FileHandlers[5].WriteString(cleartextConcepts)

	if err != nil {
		log.Fatal("Error in the writeDemodataConceptDimensionCleartextConcepts():", err)
		return err
	}

	return nil

}

func writeDemodataConceptDimensionTaggedConcepts(field string, el string) error {

	/*taggedConcepts := `INSERT INTO i2b2demodata.concept_dimension VALUES ('\medco\tagged\` + OntValues[ConceptPath{Field: field, Record: el}].Identifier + `\', 'TAG_ID:` + strconv.FormatInt(OntValues[ConceptPath{Field: field, Record: el}].Value, 10) + `', NULL, NULL, NULL, NULL, 'NOW()', NULL, NULL);` + "\n"*/

	taggedConcepts := `"\medco\tagged\` + OntValues[ConceptPath{Field: field, Record: el}].Identifier + `\","TAG_ID:` + strconv.FormatInt(OntValues[ConceptPath{Field: field, Record: el}].Value, 10) + `",,,,,"NOW()",,` + "\n"

	_, err := FileHandlers[5].WriteString(taggedConcepts)

	if err != nil {
		log.Fatal("Error in the writeDemodataConceptDimensionTaggedConcepts():", err)
		return err
	}

	return nil
}

func writeDemodataPatientMapping(el string, id int64) error {

	/*chuv := `INSERT INTO i2b2demodata.patient_mapping VALUES ('` + el + `', 'chuv', ` + strconv.FormatInt(id, 10) + `, NULL, 'Demo', NULL, NULL, NULL, 'NOW()', NULL, 1);` + "\n"*/

	chuv := `"` + el + `","chuv","` + strconv.FormatInt(id, 10) + `",,"Demo",,,,"NOW()",,"1"` + "\n"

	_, err := FileHandlers[6].WriteString(chuv)

	if err != nil {
		log.Fatal("Error in the writeDemodataPatientMapping()-Chuv:", err)
		return err
	}

	/*hive := `INSERT INTO i2b2demodata.patient_mapping VALUES ('` + strconv.FormatInt(id, 10) + `', 'HIVE', ` + strconv.FormatInt(id, 10) + `, 'A', 'HIVE', NULL, 'NOW()', 'NOW()', 'NOW()', 'edu.harvard.i2b2.crc', 1);` + "\n"*/

	hive := `"` + strconv.FormatInt(id, 10) + `","HIVE","` + strconv.FormatInt(id, 10) + `","A","HIVE",,"NOW()","NOW()","NOW()","edu.harvard.i2b2.crc","1"` + "\n"

	_, err = FileHandlers[6].WriteString(hive)

	if err != nil {
		log.Fatal("Error in the writeDemodataPatientMapping()-Hive:", err)
		return err
	}

	return nil

}

// TODO: No dummy data. Basically all flags are
func writeDemodataPatientDimension(group *onet.Roster, id int64) error {

	encryptedFlag := lib.EncryptInt(group.Aggregate, 1)
	b := encryptedFlag.ToBytes()

	/*patientDimension := `INSERT INTO i2b2demodata.patient_dimension VALUES (` + strconv.FormatInt(id, 10) + `, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'NOW()', NULL, 1, '` + base64.StdEncoding.EncodeToString(b) + `');` + "\n"*/

	patientDimension := `"` + strconv.FormatInt(id, 10) + `",,,,,,,,,,,,,,,,"NOW()",,"1","` + base64.StdEncoding.EncodeToString(b) + `"` + "\n"

	_, err := FileHandlers[7].WriteString(patientDimension)

	if err != nil {
		log.Fatal("Error in the writeDemodataPatientDimension()-Hive:", err)
		return err
	}

	return nil
}

func writeDemodataEncounterMapping(sampleID, patientID string, id int64) error {

	/*encounterChuv := `INSERT INTO i2b2demodata.encounter_mapping VALUES ('` + sampleID + `', 'chuv', 'Demo', ` + strconv.FormatInt(id, 10) + `, '` + patientID + `', 'chuv', NULL, NULL, NULL, NULL, 'NOW()', NULL, 1);` + "\n"*/

	encounterChuv := `"` + sampleID + `","chuv","Demo","` + strconv.FormatInt(id, 10) + `","` + patientID + `","chuv",,,,,"NOW()",,"1"` + "\n"

	_, err := FileHandlers[8].WriteString(encounterChuv)

	if err != nil {
		log.Fatal("Error in the writeDemodataEncounterMapping()-Chuv:", err)
		return err
	}

	/*encounterHive := `INSERT INTO i2b2demodata.encounter_mapping VALUES ('` + strconv.FormatInt(id, 10) + `', 'HIVE', 'HIVE', ` + strconv.FormatInt(id, 10) + `, '` + sampleID + `', 'chuv', 'A', NULL, 'NOW()', 'NOW()', 'NOW()', 'edu.harvard.i2b2.crc', 1);` + "\n"*/

	encounterHive := `"` + strconv.FormatInt(id, 10) + `","HIVE","HIVE","` + strconv.FormatInt(id, 10) + `","` + sampleID + `","chuv","A",,"NOW()","NOW()","NOW()","edu.harvard.i2b2.crc","1"` + "\n"

	_, err = FileHandlers[8].WriteString(encounterHive)

	if err != nil {
		log.Fatal("Error in the writeDemodataEncounterMapping()-Chuv:", err)
		return err
	}

	return nil
}

func writeDemodataVisitDimension(idV, idP int64) error {

	/*visit := `INSERT INTO i2b2demodata.visit_dimension VALUES (` + strconv.FormatInt(idV, 10) + `, ` + strconv.FormatInt(idP, 10) + `, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'NOW()', 'chuv', 1);` + "\n"*/

	visit := `"` + strconv.FormatInt(idV, 10) + `","` + strconv.FormatInt(idP, 10) + `",,,,,,,,,,,"NOW()","chuv","1"` + "\n"

	_, err := FileHandlers[9].WriteString(visit)

	if err != nil {
		log.Fatal("Error in the writeDemodataVisitDimension():", err)
		return err
	}

	return nil
}

func writeDemodataProviderDimension() error {

	/*provider := `INSERT INTO i2b2demodata.provider_dimension VALUES ('chuv', '\medco\institutions\chuv\', 'chuv', NULL, NULL, NULL, 'NOW()', NULL, 1);` + "\n"*/

	provider := `"chuv","\medco\institutions\chuv\","chuv",,,,"NOW()",,"1"` + "\n"

	_, err := FileHandlers[10].WriteString(provider)

	if err != nil {
		log.Fatal("Error in the writeDemodateProviderDimension():", err)
		return err
	}

	return nil
}

func writeDemodataObservationFactClear(el, idV, idP int64) error {

	/*clear := `INSERT INTO i2b2demodata.observation_fact VALUES (` + strconv.FormatInt(idP, 10) + `, ` + strconv.FormatInt(idV, 10), 10) + `,
	'CLEAR:` + strconv.FormatInt(el, 10) + `', 'chuv', 'NOW()', '@', 1, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	'chuv', NULL, NULL, NULL, NULL, 'NOW()', NULL, 1, ` + strconv.FormatInt(TextSearchIndex, 10) + `);` + "\n"*/

	clear := `"` + strconv.FormatInt(idP, 10) + `","` + strconv.FormatInt(idV, 10) + `","CLEAR:` + strconv.FormatInt(el, 10) + `","chuv","NOW()","@","1",,,,,,,,"chuv",,,,,"NOW()",,"1","` + strconv.FormatInt(TextSearchIndex, 10) + `"` + "\n"

	_, err := FileHandlers[11].WriteString(clear)

	if err != nil {
		log.Fatal("Error in the writeDemodataObservationFactClear():", err)
		return err
	}

	TextSearchIndex++

	return nil
}

func writeDemodataObservationFactEnc(el int64, idV, idP int64) error {

	/*encrypted := `INSERT INTO i2b2demodata.observation_fact VALUES (` + strconv.FormatInt(idP, 10) + `, ` + strconv.FormatInt(idV, 10) + `, 'TAG_ID:` + strconv.FormatInt(el, 10) + `',
	'chuv', 'NOW()', '@', 1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'chuv', NULL, NULL, NULL, NULL, 'NOW()', NULL, 1, ` + strconv.FormatInt(TextSearchIndex, 10) + `);` + "\n"*/

	encrypted := `"` + strconv.FormatInt(idP, 10) + `","` + strconv.FormatInt(idV, 10) + `","TAG_ID:` + strconv.FormatInt(el, 10) + `","chuv","NOW()","@","` + strconv.FormatInt(TextSearchIndex, 10) + `",,,,,,,,"chuv",,,,,"NOW()",,"1","` + strconv.FormatInt(TextSearchIndex, 10) + `"` + "\n"

	_, err := FileHandlers[11].WriteString(encrypted)

	if err != nil {
		log.Fatal("Error in the writeDemodataObservationFactEnc():", err)
		return err
	}

	TextSearchIndex++

	return nil

}

func containsArrayString(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func containsArrayInt64(s []int64, e int64) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
