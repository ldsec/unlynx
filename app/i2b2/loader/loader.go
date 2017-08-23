package loader

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"io"
	"os"
	"strconv"
)

// DB settings
const (
	DBuser     = "postgres"
	DBpassword = "prigen2017"
	DBname     = "test"
)

// The different paths for all the .sql files
const (
	ShrineOntClinicalSensitive       = "files/SHRINE_ONT_CLINICAL_SENSITIVE.sql"
	ShrineOntClinicalNonSensitive    = "files/SHRINE_ONT_CLINICAL_NON_SENSITIVE.sql"
	ShrineOntGenomicaAnnotations     = "files/SHRINE_ONT_GENOMIC_ANNOTATIONS.sql"
	I2B2MetadataSensitiveTagged      = "files/I2B2METADATA_SENSITIVE_TAGGED.sql"
	I2B2MetadataClinicalNonSensitive = "files/I2B2METADATA_CLINICAL_NON_SENSITIVE.sql"
	I2B2DemodataConceptDimension     = "files/I2B2DEMODATA_CONCEPT_DIMENSION.sql"
	I2B2DemodataPatientMapping       = "files/I2B2DEMODATA_PATIENT_MAPPING.sql"
	I2B2DemodataPatientDimension     = "files/I2B2DEMODATA_PATIENT_DIMENSION.sql"
	I2B2DemodataEncounterMapping     = "files/I2B2DEMODATA_ENCOUNTER_MAPPING.sql"
	I2B2DemodataVisitDimension       = "files/I2B2DEMODATA_VISIT_DIMENSION.sql"
	I2B2DemodataProviderDimension    = "files/I2B2DEMODATA_PROVIDER_DIMENSION.sql"
	I2B2DemodataObservationFact      = "files/I2B2DEMODATA_OBSERVATION_FACT.sql"
)

// File Handlers for all the .sql files
var (
	DBshrineOntClinicalSensitive       *os.File
	DBshrineOntClinicalNonSensitive    *os.File
	DBshrineOntGenomicaAnnotations     *os.File
	DBi2b2MetadataSensitiveTagged      *os.File
	DBi2b2MetadataClinicalNonSensitive *os.File
	DBi2b2DemodataConceptDimension     *os.File
	DBi2b2DemodataPatientMapping       *os.File
	DBi2b2DemodataPatientDimension     *os.File
	DBi2b2DemodataEncounterMapping     *os.File
	DBi2b2DemodataVisitDimension       *os.File
	DBi2b2DemodataProviderDimension    *os.File
	DBi2b2DemodataObservationFact      *os.File
)

// Support global variables
var (
	EncID     int64
	ClearID   int64
	OntValues map[string][]string
)

// ClinicalData stores the clinical data.
type ClinicalData struct {
	Header []string
	Data   []PatientClinical
}

// PatientClinical stores the clinical data of each patient.
type PatientClinical struct {
	Data []string
}

// GenomicData stores the genomic data.
type GenomicData struct {
	Header []string
	Data   []PatientGenomic
}

// PatientGenomic stores the genomic data of each patient.
type PatientGenomic struct {
	Data []string
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

// InitFiles creates all the .sql files
func InitFiles() error {
	var err error

	DBshrineOntClinicalSensitive, err = os.Create(ShrineOntClinicalSensitive)
	if err != nil {
		log.Fatal("Error while opening", ShrineOntClinicalSensitive)
		return err
	}

	DBshrineOntClinicalNonSensitive, err = os.Create(ShrineOntClinicalNonSensitive)
	if err != nil {
		log.Fatal("Error while opening", ShrineOntClinicalNonSensitive)
		return err
	}

	DBshrineOntGenomicaAnnotations, err = os.Create(ShrineOntGenomicaAnnotations)
	if err != nil {
		log.Fatal("Error while opening", ShrineOntGenomicaAnnotations)
		return err
	}

	DBi2b2MetadataSensitiveTagged, err = os.Create(I2B2MetadataSensitiveTagged)
	if err != nil {
		log.Fatal("Error while opening", I2B2MetadataSensitiveTagged)
		return err
	}

	DBi2b2MetadataClinicalNonSensitive, err = os.Create(I2B2MetadataClinicalNonSensitive)
	if err != nil {
		log.Fatal("Error while opening", I2B2MetadataClinicalNonSensitive)
		return err
	}

	DBi2b2DemodataConceptDimension, err = os.Create(I2B2DemodataConceptDimension)
	if err != nil {
		log.Fatal("Error while opening", I2B2DemodataConceptDimension)
		return err
	}

	DBi2b2DemodataPatientMapping, err = os.Create(I2B2DemodataPatientMapping)
	if err != nil {
		log.Fatal("Error while opening", I2B2DemodataPatientMapping)
		return err
	}

	DBi2b2DemodataPatientDimension, err = os.Create(I2B2DemodataPatientDimension)
	if err != nil {
		log.Fatal("Error while opening", I2B2DemodataPatientDimension)
		return err
	}

	DBi2b2DemodataEncounterMapping, err = os.Create(I2B2DemodataEncounterMapping)
	if err != nil {
		log.Fatal("Error while opening", I2B2DemodataEncounterMapping)
		return err
	}

	DBi2b2DemodataVisitDimension, err = os.Create(I2B2DemodataVisitDimension)
	if err != nil {
		log.Fatal("Error while opening", I2B2DemodataVisitDimension)
		return err
	}

	DBi2b2DemodataProviderDimension, err = os.Create(I2B2DemodataProviderDimension)
	if err != nil {
		log.Fatal("Error while opening", I2B2DemodataProviderDimension)
		return err
	}

	DBi2b2DemodataObservationFact, err = os.Create(I2B2DemodataObservationFact)
	if err != nil {
		log.Fatal("Error while opening", I2B2DemodataObservationFact)
		return err
	}

	EncID = int64(1)
	ClearID = int64(1)
	OntValues = make(map[string][]string)

	return nil
}

// CloseFiles closes all .sql files
func CloseFiles() {
	DBshrineOntClinicalSensitive.Close()
	DBshrineOntClinicalNonSensitive.Close()
	DBshrineOntGenomicaAnnotations.Close()
	DBi2b2MetadataSensitiveTagged.Close()
	DBi2b2MetadataClinicalNonSensitive.Close()
	DBi2b2DemodataConceptDimension.Close()
	DBi2b2DemodataPatientMapping.Close()
	DBi2b2DemodataPatientDimension.Close()
	DBi2b2DemodataEncounterMapping.Close()
	DBi2b2DemodataVisitDimension.Close()
	DBi2b2DemodataProviderDimension.Close()
	DBi2b2DemodataObservationFact.Close()
}

// LoadDataFiles loads the data from the dataset and populates the .sql scripts
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
		if string(record[0]) == "" || string(record[0][0:1]) != "#" {

			// the HEADER
			if first == true {
				for i := 2; i < len(record); i++ {
					writeShrineOntologyEnc(record[i])
					writeShrineOntologyClear(record[i])

					writeMetadataOntologyClear(record[i])

					headerClinical = append(headerClinical, record[i])

				}
				first = false
			} else {
				for i, j := 2, 0; i < len(record); i, j = i+1, j+1 {

					if record[i] == "" {
						record[i] = "<empty>"
					}

					if contains(OntValues[headerClinical[j]], record[i]) == false {
						// add headers to shrine_ont.clinical_sensitive
						writeShrineOntologyLeafEnc(headerClinical[j], record[i])
						writeShrineOntologyLeafClear(headerClinical[j], record[i])

						writeMetadataOntologyLeafClear(headerClinical[j], record[i])

						OntValues[headerClinical[j]] = append(OntValues[headerClinical[j]], record[i])
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
				   'NOW()', NULL, NULL, NULL, 'ENC_ID', '@', NULL, NULL, NULL, NULL);` + "\n"

	_, err := DBshrineOntClinicalSensitive.WriteString(clinicalSensitive)

	if err != nil {
		log.Fatal("Error in the writeShrineOntologyEnc():", err)
		return err
	}

	return nil
}

func writeShrineOntologyLeafEnc(field, el string) error {

	clinicalSensitive := `INSERT INTO shrine_ont.clinical_sensitive VALUES (4, '\\medco\\clinical\\sensitive\\` + field + `\\` + el + `\\', '` + el + `', 'N', 'LA', NULL, 'ENC_ID:` + strconv.FormatInt(EncID,10) + `', NULL, 'concept_cd', 'concept_dimension', 'concept_path', 'T', 'LIKE',
			  '\\medco\\clinical\\sensitive\\` + field + `\\` + el + `\\', 'Sensitive value encrypted by Unlynx',  '\\medco\\clinical\\sensitive\\` + field + `\\` + el + `\\',
			   'NOW()', NULL, NULL, NULL, 'ENC_ID', '@', NULL, NULL, NULL, NULL);` + "\n"

	_, err := DBshrineOntClinicalSensitive.WriteString(clinicalSensitive)
	EncID++

	if err != nil {
		log.Fatal("Error in the writeShrineOntologyLeafEnc():", err)
		return err
	}

	return nil
}

func writeShrineOntologyClear(el string) error {

	clinical := `INSERT INTO shrine_ont.clinical_non_sensitive VALUES (3, '\\medco\\clinical\\nonsensitive\\` + el + `\\', '` + el + `', 'N', 'CA', NULL, NULL, NULL, 'concept_cd', 'concept_dimension', 'concept_path', 'T', 'LIKE',
				  '\\medco\\clinical\\nonsensitive\\` + el + `\\', 'Non-sensitive field', '\\medco\\clinical\\nonsensitive\\` + el + `\\',
				   'NOW()', NULL, NULL, NULL, 'CLEAR', '@', NULL, NULL, NULL, NULL);` + "\n"

	_, err := DBshrineOntClinicalNonSensitive.WriteString(clinical)

	if err != nil {
		log.Fatal("Error in the writeShrineOntologyClear():", err)
		return err
	}

	return nil
}

func writeShrineOntologyLeafClear(field, el string) error {
	clinical := `INSERT INTO shrine_ont.clinical_non_sensitive VALUES (4, '\\medco\\clinical\\nonsensitive\\` + field + `\\` + el + `\\', '` + el + `', 'N', 'LA', NULL, 'CLEAR:` + strconv.FormatInt(ClearID, 10) + `', NULL, 'concept_cd', 'concept_dimension', 'concept_path', 'T', 'LIKE',
			  '\\medco\\clinical\\nonsensitive\\` + field + `\\` + el + `\\', 'Non-sensitive value',  '\\medco\\clinical\\sensitive\\` + field + `\\` + el + `\\',
			   'NOW()', NULL, NULL, NULL, 'CLEAR', '@', NULL, NULL, NULL, NULL);` + "\n"

	_, err := DBshrineOntClinicalNonSensitive.WriteString(clinical)

	if err != nil {
		log.Fatal("Error in the writeShrineOntologyLeafClear():", err)
		return err
	}

	return nil
}

func writeMetadataOntologyClear(el string) error {

	clinical := `INSERT INTO i2b2metadata.clinical_non_sensitive VALUES (3, '\\medco\\clinical\\nonsensitive\\` + el + `\\', '` + el + `', 'N', 'CA', NULL, NULL, NULL, 'concept_cd', 'concept_dimension', 'concept_path', 'T', 'LIKE',
				  '\\medco\\clinical\\nonsensitive\\` + el + `\\', 'Non-sensitive field', '\\medco\\clinical\\nonsensitive\\` + el + `\\',
				   'NOW()', NULL, NULL, NULL, 'CLEAR', '@', NULL, NULL, NULL, NULL);` + "\n"

	_, err := DBi2b2MetadataClinicalNonSensitive.WriteString(clinical)

	if err != nil {
		log.Fatal("Error in the writeMetadataOntologyClear():", err)
		return err
	}

	return nil
}

func writeMetadataOntologyLeafClear(field, el string) error {
	clinical := `INSERT INTO i2b2metadata.clinical_non_sensitive VALUES (4, '\\medco\\clinical\\nonsensitive\\` + field + `\\` + el + `\\', '` + el + `', 'N', 'LA', NULL, 'CLEAR:` + strconv.FormatInt(ClearID,10) + `', NULL, 'concept_cd', 'concept_dimension', 'concept_path', 'T', 'LIKE',
			  '\\medco\\clinical\\nonsensitive\\` + field + `\\` + el + `\\', 'Non-sensitive value',  '\\medco\\clinical\\sensitive\\` + field + `\\` + el + `\\',
			   'NOW()', NULL, NULL, NULL, 'CLEAR', '@', NULL, NULL, NULL, NULL);` + "\n"

	_, err := DBi2b2MetadataClinicalNonSensitive.WriteString(clinical)
	ClearID++

	if err != nil {
		log.Fatal("Error in the writeMetadataOntologyLeafClear():", err)
		return err
	}

	return nil
}

func connectDB() (*sql.DB, error) {
	dbinfo := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable",
		DBuser, DBpassword, DBname)
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
