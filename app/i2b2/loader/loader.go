package loader

import (
	"database/sql"
	_ "github.com/lib/pq"
	"gopkg.in/dedis/onet.v1"
	"os"
	"fmt"
	"gopkg.in/dedis/onet.v1/log"
	"encoding/csv"
	"io"
	"strconv"
)

const (
	DB_USER     = "postgres"
	DB_PASSWORD = "prigen2017"
	DB_NAME     = "test"

	SHRINE_ONT_CLINICAL_SENSITIVE = "files/SHRINE_ONT_CLINICAL_SENSITIVE.sql"
	SHRINE_ONT_CLINICAL_NON_SENSITIVE = "files/SHRINE_ONT_CLINICAL_NON_SENSITIVE.sql"
	SHRINE_ONT_GENOMIC_ANNOTATIONS = "files/SHRINE_ONT_GENOMIC_ANNOTATIONS.sql"
	I2B2METADATA_SENSITIVE_TAGGED = "files/I2B2METADATA_SENSITIVE_TAGGED.sql"
	I2B2METADATA_CLINICAL_NON_SENSITIVE = "files/I2B2METADATA_CLINICAL_NON_SENSITIVE.sql"
	I2B2METADATA_CONCEPT_DIMENSION = "files/I2B2METADATA_CONCEPT_DIMENSION.sql"
	I2B2METADATA_PATIENT_MAPPING = "files/I2B2METADATA_PATIENT_MAPPING.sql"
	I2B2METADATA_PATIENT_DIMENSION = "files/I2B2METADATA_PATIENT_DIMENSION.sql"
	I2B2METADATA_ENCOUNTER_MAPPING = "files/I2B2METADATA_ENCOUNTER_MAPPING.sql"
	I2B2METADATA_VISIT_DIMENSION = "files/I2B2METADATA_VISIT_DIMENSION.sql"
	I2B2METADATA_PROVIDER_DIMENSION = "files/I2B2METADATA_PROVIDER_DIMENSION.sql"
	I2B2METADATA_OBSERVATION_FACT = "files/I2B2METADATA_OBSERVATION_FACT.sql"
)

var (
	DB_SHRINE_ONT_CLINICAL_SENSITIVE *os.File
	DB_SHRINE_ONT_CLINICAL_NON_SENSITIVE *os.File
	DB_SHRINE_ONT_GENOMIC_ANNOTATIONS *os.File
	DB_I2B2METADATA_SENSITIVE_TAGGED *os.File
	DB_I2B2METADATA_CLINICAL_NON_SENSITIVE *os.File
	DB_I2B2METADATA_CONCEPT_DIMENSION *os.File
	DB_I2B2METADATA_PATIENT_MAPPING *os.File
	DB_I2B2METADATA_PATIENT_DIMENSION *os.File
	DB_I2B2METADATA_ENCOUNTER_MAPPING *os.File
	DB_I2B2METADATA_VISIT_DIMENSION *os.File
	DB_I2B2METADATA_PROVIDER_DIMENSION *os.File
	DB_I2B2METADATA_OBSERVATION_FACT *os.File

	ENC_ID int64
	CLEAR_ID int64
	ONT_VALUES map[string][]string
)

// ClinicalData stores the clinical data.
type ClinicalData struct {
	Header 	[]string
	Data 	[]PatientClinical
}

// PatientClinical stores the clinical data of each patient.
type PatientClinical struct {
	Data   []string
}

// GenomicData stores the genomic data.
type GenomicData struct {
	Header 	[]string
	Data 	[]PatientGenomic
}
// PatientGenomic stores the genomic data of each patient.
type PatientGenomic struct {
	Data   []string
}

// LoadClient initiates the loading process
func LoadClient(el *onet.Roster, fClinical *os.File, fGenomic *os.File) error {
	db, err := connectDB()
	if err != nil {
		return err
	}

	err = InitFiles()
	if err != nil {
		log.Fatal("Error while creating the necessary sql files", err)
		return err
	}

	err = LoadDataFiles(fClinical, fGenomic)

	/*err = writeShrineOntology("shrine_ontolgy.sql", clinicalData[0].Header)
	if err != nil {
		log.Fatal("Error while generating the Shrine Ontology sql file", err)
		return err
	}*/


	CloseFiles()
	db.Close()
	return nil
}

func InitFiles() error{
	var err error

	DB_SHRINE_ONT_CLINICAL_SENSITIVE, err = os.Create(SHRINE_ONT_CLINICAL_SENSITIVE)
	if err != nil {
		log.Fatal("Error while opening", SHRINE_ONT_CLINICAL_SENSITIVE)
		return err
	}

	DB_SHRINE_ONT_CLINICAL_NON_SENSITIVE, err = os.Create(SHRINE_ONT_CLINICAL_NON_SENSITIVE)
	if err != nil {
		log.Fatal("Error while opening", SHRINE_ONT_CLINICAL_NON_SENSITIVE)
		return err
	}

	DB_SHRINE_ONT_GENOMIC_ANNOTATIONS, err = os.Create(SHRINE_ONT_GENOMIC_ANNOTATIONS)
	if err != nil {
		log.Fatal("Error while opening", SHRINE_ONT_GENOMIC_ANNOTATIONS)
		return err
	}

	DB_I2B2METADATA_SENSITIVE_TAGGED, err = os.Create(I2B2METADATA_SENSITIVE_TAGGED)
	if err != nil {
		log.Fatal("Error while opening", I2B2METADATA_SENSITIVE_TAGGED)
		return err
	}

	DB_I2B2METADATA_CLINICAL_NON_SENSITIVE, err = os.Create(I2B2METADATA_CLINICAL_NON_SENSITIVE)
	if err != nil {
		log.Fatal("Error while opening", I2B2METADATA_CLINICAL_NON_SENSITIVE)
		return err
	}

	DB_I2B2METADATA_CONCEPT_DIMENSION, err = os.Create(I2B2METADATA_CONCEPT_DIMENSION)
	if err != nil {
		log.Fatal("Error while opening", I2B2METADATA_CONCEPT_DIMENSION)
		return err
	}

	DB_I2B2METADATA_PATIENT_MAPPING, err = os.Create(I2B2METADATA_PATIENT_MAPPING)
	if err != nil {
		log.Fatal("Error while opening", I2B2METADATA_PATIENT_MAPPING)
		return err
	}

	DB_I2B2METADATA_PATIENT_DIMENSION, err = os.Create(I2B2METADATA_PATIENT_DIMENSION)
	if err != nil {
		log.Fatal("Error while opening", I2B2METADATA_PATIENT_DIMENSION)
		return err
	}

	DB_I2B2METADATA_ENCOUNTER_MAPPING, err = os.Create(I2B2METADATA_ENCOUNTER_MAPPING)
	if err != nil {
		log.Fatal("Error while opening", I2B2METADATA_ENCOUNTER_MAPPING)
		return err
	}

	DB_I2B2METADATA_VISIT_DIMENSION, err = os.Create(I2B2METADATA_VISIT_DIMENSION)
	if err != nil {
		log.Fatal("Error while opening", I2B2METADATA_VISIT_DIMENSION)
		return err
	}

	DB_I2B2METADATA_PROVIDER_DIMENSION, err = os.Create(I2B2METADATA_PROVIDER_DIMENSION)
	if err != nil {
		log.Fatal("Error while opening", I2B2METADATA_PROVIDER_DIMENSION)
		return err
	}

	DB_I2B2METADATA_OBSERVATION_FACT, err = os.Create(I2B2METADATA_OBSERVATION_FACT)
	if err != nil {
		log.Fatal("Error while opening", I2B2METADATA_OBSERVATION_FACT)
		return err
	}

	ENC_ID = int64(1)
	CLEAR_ID = int64(1)
	ONT_VALUES = make(map[string][]string)

	return nil
}

func CloseFiles(){
	DB_SHRINE_ONT_CLINICAL_SENSITIVE.Close()
	DB_SHRINE_ONT_CLINICAL_NON_SENSITIVE.Close()
	DB_SHRINE_ONT_GENOMIC_ANNOTATIONS.Close()
	DB_I2B2METADATA_SENSITIVE_TAGGED.Close()
	DB_I2B2METADATA_CLINICAL_NON_SENSITIVE.Close()
	DB_I2B2METADATA_CONCEPT_DIMENSION.Close()
	DB_I2B2METADATA_PATIENT_MAPPING.Close()
	DB_I2B2METADATA_PATIENT_DIMENSION.Close()
	DB_I2B2METADATA_ENCOUNTER_MAPPING.Close()
	DB_I2B2METADATA_VISIT_DIMENSION.Close()
	DB_I2B2METADATA_PROVIDER_DIMENSION.Close()
	DB_I2B2METADATA_OBSERVATION_FACT.Close()
}

func LoadDataFiles(fClinical *os.File, fGenomic *os.File) error {

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
		if string(record[0])=="" || string(record[0][0:1]) != "#" {

			// the HEADER
			if first == true {
				for i:=2; i<len(record); i++ {
					writeShrineOntologyEnc(record[i])
					writeShrineOntologyClear(record[i])

					writeMetadataOntologyClear(record[i])

					headerClinical = append(headerClinical, record[i])

				}
				first = false
			} else {
				for i, j := 2, 0; i<len(record); i, j = i+1, j+1  {

					if record[i] == "" {
						record[i] = "<empty>"
					}

					if contains(ONT_VALUES[headerClinical[j]], record[i]) == false {
						// add headers to shrine_ont.clinical_sensitive
						writeShrineOntologyLeafEnc(headerClinical[j], record[i])
						writeShrineOntologyLeafClear(headerClinical[j], record[i])

						writeMetadataOntologyLeafClear(headerClinical[j], record[i])

						ONT_VALUES[headerClinical[j]] = append(ONT_VALUES[headerClinical[j]], record[i])
					}
				}
			}

		}
	}

	fClinical.Close()

	// load genomic
	/*reader = csv.NewReader(fGenomic)
	reader.Comma = '\t'

	first = true
	headerGenomic := make([]string, 0)
	genomic := make([]PatientGenomic, 0)

	i := 0
	for {
		// read just one record, but we could ReadAll() as well
		record, err := reader.Read()
		// end-of-file is fitted into err
		if err == io.EOF {
			break
		} else if err != nil {
			return ClinicalData{}, GenomicData{}, err
		}

		// if it is not a commented line
		if string(record[0])=="" || string(record[0][0:1]) != "#" {

			// the HEADER
			if first == true {
				for _, el := range record {
					headerGenomic = append(headerGenomic, el)
				}
				first = false
			} else {
				data := make([]string,0)
				for _, el := range record {
					data = append(data, el)
				}

				genomic = append(genomic, PatientGenomic{Data: data})
			}

		}
		i++
	}

	fGenomic.Close()*/

	return nil
}

func writeShrineOntologyEnc(el string) error {

	clinicalSensitive := `INSERT INTO shrine_ont.clinical_sensitive VALUES (3, '\\medco\\clinical\\sensitive\\` + el + `\\', '` + el + `', 'N', 'CA', NULL, NULL, NULL, 'concept_cd', 'concept_dimension', 'concept_path', 'T', 'LIKE',
				  '\\medco\\clinical\\sensitive\\` + el + `\\', 'Sensitive field encrypted by Unlynx', '\\medco\\clinical\\sensitive\\` + el + `\\',
				   'NOW()', NULL, NULL, NULL, 'ENC_ID', '@', NULL, NULL, NULL, NULL);`+"\n"

	_, err := DB_SHRINE_ONT_CLINICAL_SENSITIVE.WriteString(clinicalSensitive)

	if err != nil {
		log.Fatal("Error in the writeShrineOntologyEnc():", err)
		return err
	}

	return nil
}

func writeShrineOntologyLeafEnc(field, el string) error {

	clinicalSensitive := `INSERT INTO shrine_ont.clinical_sensitive VALUES (4, '\\medco\\clinical\\sensitive\\` + field + `\\` + el + `\\', '` + el + `', 'N', 'LA', NULL, 'ENC_ID:` + strconv.Itoa(ENC_ID) + `', NULL, 'concept_cd', 'concept_dimension', 'concept_path', 'T', 'LIKE',
			  '\\medco\\clinical\\sensitive\\` + field + `\\` + el + `\\', 'Sensitive value encrypted by Unlynx',  '\\medco\\clinical\\sensitive\\` + field + `\\` + el + `\\',
			   'NOW()', NULL, NULL, NULL, 'ENC_ID', '@', NULL, NULL, NULL, NULL);`+"\n"


	_, err := DB_SHRINE_ONT_CLINICAL_SENSITIVE.WriteString(clinicalSensitive)
	ENC_ID++

	if err != nil {
		log.Fatal("Error in the writeShrineOntologyLeafEnc():", err)
		return err
	}

	return nil
}

func writeShrineOntologyClear(el string) error {

	clinical := `INSERT INTO shrine_ont.clinical_non_sensitive VALUES (3, '\\medco\\clinical\\nonsensitive\\` + el + `\\', '` + el + `', 'N', 'CA', NULL, NULL, NULL, 'concept_cd', 'concept_dimension', 'concept_path', 'T', 'LIKE',
				  '\\medco\\clinical\\nonsensitive\\` + el + `\\', 'Non-sensitive field', '\\medco\\clinical\\nonsensitive\\` + el + `\\',
				   'NOW()', NULL, NULL, NULL, 'CLEAR', '@', NULL, NULL, NULL, NULL);`+"\n"

	_, err := DB_SHRINE_ONT_CLINICAL_NON_SENSITIVE.WriteString(clinical)

	if err != nil {
		log.Fatal("Error in the writeShrineOntologyClear():", err)
		return err
	}

	return nil
}

func writeShrineOntologyLeafClear(field, el string) error {
	clinical := `INSERT INTO shrine_ont.clinical_non_sensitive VALUES (4, '\\medco\\clinical\\nonsensitive\\` + field + `\\` + el + `\\', '` + el + `', 'N', 'LA', NULL, 'CLEAR:` + strconv.Itoa(CLEAR_ID) + `', NULL, 'concept_cd', 'concept_dimension', 'concept_path', 'T', 'LIKE',
			  '\\medco\\clinical\\nonsensitive\\` + field + `\\` + el + `\\', 'Non-sensitive value',  '\\medco\\clinical\\sensitive\\` + field + `\\` + el + `\\',
			   'NOW()', NULL, NULL, NULL, 'CLEAR', '@', NULL, NULL, NULL, NULL);`+"\n"


	_, err := DB_SHRINE_ONT_CLINICAL_NON_SENSITIVE.WriteString(clinical)

	if err != nil {
		log.Fatal("Error in the writeShrineOntologyLeafClear():", err)
		return err
	}

	return nil
}

func writeMetadataOntologyClear(el string) error {

	clinical := `INSERT INTO i2b2metadata.clinical_non_sensitive VALUES (3, '\\medco\\clinical\\nonsensitive\\` + el + `\\', '` + el + `', 'N', 'CA', NULL, NULL, NULL, 'concept_cd', 'concept_dimension', 'concept_path', 'T', 'LIKE',
				  '\\medco\\clinical\\nonsensitive\\` + el + `\\', 'Non-sensitive field', '\\medco\\clinical\\nonsensitive\\` + el + `\\',
				   'NOW()', NULL, NULL, NULL, 'CLEAR', '@', NULL, NULL, NULL, NULL);`+"\n"

	_, err := DB_I2B2METADATA_CLINICAL_NON_SENSITIVE.WriteString(clinical)

	if err != nil {
		log.Fatal("Error in the writeMetadataOntologyClear():", err)
		return err
	}

	return nil
}

func writeMetadataOntologyLeafClear(field, el string) error {
	clinical := `INSERT INTO i2b2metadata.clinical_non_sensitive VALUES (4, '\\medco\\clinical\\nonsensitive\\` + field + `\\` + el + `\\', '` + el + `', 'N', 'LA', NULL, 'CLEAR:` + strconv.Itoa(CLEAR_ID) + `', NULL, 'concept_cd', 'concept_dimension', 'concept_path', 'T', 'LIKE',
			  '\\medco\\clinical\\nonsensitive\\` + field + `\\` + el + `\\', 'Non-sensitive value',  '\\medco\\clinical\\sensitive\\` + field + `\\` + el + `\\',
			   'NOW()', NULL, NULL, NULL, 'CLEAR', '@', NULL, NULL, NULL, NULL);`+"\n"


	_, err := DB_I2B2METADATA_CLINICAL_NON_SENSITIVE.WriteString(clinical)
	CLEAR_ID++

	if err != nil {
		log.Fatal("Error in the writeMetadataOntologyLeafClear():", err)
		return err
	}

	return nil
}

func connectDB() (*sql.DB, error) {
	dbinfo := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable",
		DB_USER, DB_PASSWORD, DB_NAME)
	db, err := sql.Open("postgres", dbinfo)
	return db, err
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
