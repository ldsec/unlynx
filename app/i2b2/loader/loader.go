package loader

import (
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"fmt"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/services/i2b2"
	"gopkg.in/dedis/crypto.v0/base64"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"io"
	"os"
	"strconv"
	"strings"
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

// PatientVisitLink contains both the link between the patient and the visit/encounter (patient ID and sample ID)
type PatientVisitLink struct {
	PatientID   int64
	EncounterID int64
}

// ConceptPath defines the end of the concept path tree and we use it in a map so that we do not repeat values
type ConceptPath struct {
	Field  string
	Record string
}

// Support global variables
var (
	EncID           int64
	ClearID         int64
	PatientID       int64
	EncounterID     int64
	AllSensitiveIDs []int64
)

// LoadClient initiates the loading process
func LoadClient(el *onet.Roster, entryPointIdx int, fClinical *os.File, fGenomic *os.File, listSensitive []string, replay int) error {
	db, err := connectDB()
	if err != nil {
		return err
	}

	err = InitFiles()
	if err != nil {
		log.Fatal("Error while creating the necessary sql files", err)
		return err
	}

	err = LoadDataFiles(el, entryPointIdx, fClinical, fGenomic, listSensitive, replay)
	if err != nil {
		log.Fatal("Error while generating the sql files", err)
		return err
	}

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
	PatientID = int64(1)
	EncounterID = int64(1)
	AllSensitiveIDs = make([]int64, 0)

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

// Replays the Dataset x number of times
func ReplayDataset(x int){

}

// LoadDataFiles loads the data from the dataset and populates the .sql scripts
func LoadDataFiles(group *onet.Roster, entryPointIdx int, fClinical *os.File, fGenomic *os.File, listSensitive []string, replay int) error {
	if replay>1{
		ReplayDataset(replay)
	}

	if err := writeDemodataProviderDimension(); err != nil {return err}

	ontValues := make(map[ConceptPath]int64)
	patientVisitLinkList := make([]PatientVisitLink, 0)
	// maps encounters/sample ID to Patient and Encounter numbers
	patientVisitMap := make(map[string]PatientVisitLink)

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

					// sensitive
					if containsArrayString(listSensitive, record[i]) == true || (len(listSensitive) == 1 && listSensitive[0] == "all") {
						if err := writeShrineOntologyEnc(record[i]); err != nil {return err}
						// we don't generate the MetadataOntologyEnc because we will do this afterwards (so that we only perform 1 DDT with all sensitive elements)
					} else {
						if err := writeShrineOntologyClear(record[i]); err != nil {return err}
						if err := writeMetadataOntologyClear(record[i]); err != nil {return err}
					}
					headerClinical = append(headerClinical, record[i])

				}
				first = false
			} else {
				if err := writeDemodataPatientMapping(record[1]); err != nil {return err}
				if err := writeDemodataPatientDimension(group); err != nil {return err}

				if err := writeDemodataEncounterMapping(record[0], record[1]); err != nil {return err}
				if err := writeDemodataVisitDimension(); err != nil {return err}

				patientVisitMap[record[0]] = PatientVisitLink{PatientID: PatientID, EncounterID: EncounterID}

				for i, j := 2, 0; i < len(record); i, j = i+1, j+1 {

					if record[i] == "" {
						record[i] = "<empty>"
					}

					// sensitive
					if containsArrayString(listSensitive, headerClinical[j]) == true || (len(listSensitive) == 1 && listSensitive[0] == "all") {

						// if concept path does not exist
						if _, ok := ontValues[ConceptPath{Field: headerClinical[j], Record: record[i]}]; ok == false {
							if err := writeShrineOntologyLeafEnc(headerClinical[j], record[i]); err != nil {return err}
							// we don't generate the MetadataOntologyLeafEnc because we will do this afterwards (so that we only perform 1 DDT with all sensitive elements)

							ontValues[ConceptPath{Field: headerClinical[j], Record: record[i]}] = EncID
							EncID++
						}

						patientVisitLinkList = append(patientVisitLinkList, PatientVisitLink{PatientID: PatientID, EncounterID: EncounterID})
						AllSensitiveIDs = append(AllSensitiveIDs, ontValues[ConceptPath{Field: headerClinical[j], Record: record[i]}])
					} else {

						// if concept path does not exist
						if _, ok := ontValues[ConceptPath{Field: headerClinical[j], Record: record[i]}]; ok == false {
							if err := writeShrineOntologyLeafClear(headerClinical[j], record[i]); err != nil {return err}
							if err := writeMetadataOntologyLeafClear(headerClinical[j], record[i]); err != nil {return err}
							if err := writeDemodataConceptDimensionCleartextConcepts(headerClinical[j], record[i]); err != nil {return err}

							ontValues[ConceptPath{Field: headerClinical[j], Record: record[i]}] = ClearID
							ClearID++
						}

						if err := writeDemodataObservationFactClear(ontValues[ConceptPath{Field: headerClinical[j], Record: record[i]}]); err != nil {return err}
					}

				}

				PatientID++
				EncounterID++
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
		if string(record[0]) == "" || string(record[0][0:1]) != "#" {

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
				genomicID, err := writeShrineOntologyGenomicAnnotations(headerGenomic, indexGenVariant, record)

				if err == nil{
					patientVisitLinkList = append(patientVisitLinkList, PatientVisitLink{PatientID: patientVisitMap[headerGenomic[indexGenVariant["Tumor_Sample_Barcode"]]].PatientID,
						EncounterID: patientVisitMap[headerGenomic[indexGenVariant["Tumor_Sample_Barcode"]]].EncounterID})
					AllSensitiveIDs = append(AllSensitiveIDs, genomicID)
				} else if err != nil && genomicID == int64(-1) { // if it is a fatal error
					return err
				}
			}

		}
	}

	fGenomic.Close()

	log.LLvl1("Finished parsing the genomic dataset...")

	// write the tagged values
	taggedValues, err := encryptAndTag(AllSensitiveIDs, group, entryPointIdx)
	if err != nil {
		return err
	}
	if err := writeMetadataSensitiveTagged(taggedValues, patientVisitLinkList); err != nil {return err}

	log.LLvl1("The End.")

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

	clinicalSensitive := `INSERT INTO shrine_ont.clinical_sensitive VALUES (4, '\\medco\\clinical\\sensitive\\` + field + `\\` + el + `\\', '` + el + `', 'N', 'LA', NULL, 'ENC_ID:` + strconv.FormatInt(EncID, 10) + `', NULL, 'concept_cd', 'concept_dimension', 'concept_path', 'T', 'LIKE',
			  '\\medco\\clinical\\sensitive\\` + field + `\\` + el + `\\', 'Sensitive value encrypted by Unlynx',  '\\medco\\clinical\\sensitive\\` + field + `\\` + el + `\\',
			   'NOW()', NULL, NULL, NULL, 'ENC_ID', '@', NULL, NULL, NULL, NULL);` + "\n"

	_, err := DBshrineOntClinicalSensitive.WriteString(clinicalSensitive)

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

func writeShrineOntologyGenomicAnnotations(fields []string, indexGenVariant map[string]int, record []string) (int64, error) {

	// if the ref and alt are too big ignore them (for now....)
	if len(record[indexGenVariant["Reference_Allele"]]) > 6 || len(record[indexGenVariant["Tumor_Seq_Allele1"]]) > 6 {
		return int64(0), errors.New("Reference and/or Alternate base size is bigger than the maximum allowed")
	}

	// generate id
	aux, err := strconv.ParseInt(record[indexGenVariant["Start_Position"]], 10, 64)
	if err != nil {
		log.Fatal("Error while parsing Start Position")
		return int64(-1), err
	}

	id, err := GetVariantID(record[indexGenVariant["Chromosome"]], aux, record[indexGenVariant["Reference_Allele"]], record[indexGenVariant["Tumor_Seq_Allele1"]])
	if err != nil {
		log.Fatal("Error while generating the genomic id")
		return int64(-1), err
	}

	// if genomic id already exist we don't need to add it to the shrine_ont.genomic_annotations
	if containsArrayInt64(AllSensitiveIDs, id) == true {
		return id, nil
	}

	otherFields := ""
	for i, el := range record {
		if _, ok := indexGenVariant[el]; ok == false{
			otherFields += fields[i] + ":" + strings.Replace(el, "'", "''", -1) + ", "
		}
	}
	// remove the last ", "
	otherFields = otherFields[:len(otherFields)-2]

	annotation := `INSERT INTO shrine_ont.genomic_annotations VALUES ('` + strconv.FormatInt(id, 10) + `', '{ ` + otherFields + `}');` + "\n"

	_, err = DBshrineOntGenomicaAnnotations.WriteString(annotation)

	if err != nil {
		log.Fatal("Error in the writeShrineOntologyGenomicAnnotations():", err)
		return int64(-1), err
	}

	return id, nil
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

func encryptAndTag(list []int64, group *onet.Roster, entryPointIdx int) ([]lib.GroupingKey, error) {

	// ENCRYPTION
	listEncryptedElements := make(lib.CipherVector, len(list))

	for i := int64(0); i < int64(len(list)); i++ {
		listEncryptedElements[i] = *lib.EncryptInt(group.Aggregate, list[i])
	}
	log.LLvl1("Finished encrypting the sensitive data...")

	// TAGGING
	client := serviceI2B2.NewUnLynxClient(group.List[entryPointIdx], strconv.Itoa(entryPointIdx))
	_, result, _, err := client.SendSurveyDDTRequestTerms(
		group, // Roster
		serviceI2B2.SurveyID("tagging_loading_phase"), // SurveyID
		listEncryptedElements,                         // Encrypted query terms to tag
		false, // compute proofs?
	)

	if err != nil {
		log.Fatal("Error during DDT")
		return nil, err
	}

	log.LLvl1("Finished tagging the sensitive data...")

	return result, nil
}

func writeMetadataSensitiveTagged(list []lib.GroupingKey, patientVisitLinkList []PatientVisitLink) error {

	if len(list) != len(patientVisitLinkList) {
		log.Fatal("The number of sensitive elements does not match the number of 'PatientVisitLink's.")
		return errors.New("")
	}

	tagValues := make(map[string]int64)
	tagIDs := make(map[int64]bool)

	for i, el := range list {

		// if element el does not exist yet
		if _, okTagV := tagValues[string(el)]; okTagV == false {
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
			tagValues[string(el)] = int64(tagID)

			sensitive := `INSERT INTO i2b2metadata.sensitive_tagged VALUES (2, '\\medco\\tagged\\` + string(el) + `\\', '', 'N', 'LA ', NULL, 'TAG_ID:` + strconv.FormatUint(uint64(tagID), 10) + `', NULL, 'concept_cd', 'concept_dimension', 'concept_path', 'T', 'LIKE',
			'\\medco\\tagged\\` + string(el) + `\\', NULL, NULL, 'NOW()', NULL, NULL, NULL, 'TAG_ID', '@', NULL, NULL, NULL, NULL);` + "\n"

			_, err := DBi2b2MetadataSensitiveTagged.WriteString(sensitive)

			if err != nil {
				log.Fatal("Error in the writeMetadataSensitiveTagged():", err)
				return err
			}

			if err := writeDemodataConceptDimensionTaggedConcepts(string(el), strconv.FormatUint(uint64(tagValues[string(el)]), 10)); err != nil {return err}

		}

		if err := writeDemodataObservationFactEnc(strconv.FormatUint(uint64(tagValues[string(el)]), 10), patientVisitLinkList[i]); err != nil {return err}
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
	clinical := `INSERT INTO i2b2metadata.clinical_non_sensitive VALUES (4, '\\medco\\clinical\\nonsensitive\\` + field + `\\` + el + `\\', '` + el + `', 'N', 'LA', NULL, 'CLEAR:` + strconv.FormatInt(ClearID, 10) + `', NULL, 'concept_cd', 'concept_dimension', 'concept_path', 'T', 'LIKE',
			  '\\medco\\clinical\\nonsensitive\\` + field + `\\` + el + `\\', 'Non-sensitive value',  '\\medco\\clinical\\sensitive\\` + field + `\\` + el + `\\',
			   'NOW()', NULL, NULL, NULL, 'CLEAR', '@', NULL, NULL, NULL, NULL);` + "\n"

	_, err := DBi2b2MetadataClinicalNonSensitive.WriteString(clinical)

	if err != nil {
		log.Fatal("Error in the writeMetadataOntologyLeafClear():", err)
		return err
	}

	return nil
}

func writeDemodataConceptDimensionCleartextConcepts(field, el string) error {

	cleartextConcepts := `INSERT INTO i2b2demodata.concept_dimension VALUES ('\\medco\\clinical\\nonsensitive\\` + field + `\\` + el + `\\', 'CLEAR:` + strconv.FormatInt(ClearID, 10) + `', '` + el + `', NULL, NULL, NULL, 'NOW()', NULL, NULL);` + "\n"

	_, err := DBi2b2DemodataConceptDimension.WriteString(cleartextConcepts)

	if err != nil {
		log.Fatal("Error in the writeDemodataConceptDimensionCleartextConcepts():", err)
		return err
	}

	return nil

}

func writeDemodataConceptDimensionTaggedConcepts(el string, id string) error {

	taggedConcepts := `INSERT INTO i2b2demodata.concept_dimension VALUES ('\\medco\\tagged\\` + el + `\\', 'TAG_ID:` + id + `', NULL, NULL, NULL, NULL, 'NOW()', NULL, NULL);` + "\n"

	_, err := DBi2b2DemodataConceptDimension.WriteString(taggedConcepts)

	if err != nil {
		log.Fatal("Error in the writeDemodataConceptDimensionTaggedConcepts():", err)
		return err
	}

	return nil
}

func writeDemodataPatientMapping(el string) error {

	chuv := `INSERT INTO i2b2demodata.patient_mapping VALUES ('` + el + `', 'chuv', ` + strconv.FormatInt(PatientID, 10) + `, NULL, 'Demo', NULL, NULL, NULL, 'NOW()', NULL, 1);` + "\n"

	_, err := DBi2b2DemodataPatientMapping.WriteString(chuv)

	if err != nil {
		log.Fatal("Error in the writeDemodataPatientMapping()-Chuv:", err)
		return err
	}

	hive := `INSERT INTO i2b2demodata.patient_mapping VALUES ('` + strconv.FormatInt(PatientID, 10) + `', 'HIVE', ` + strconv.FormatInt(PatientID, 10) + `, 'A', 'HIVE', NULL, 'NOW()', 'NOW()', 'NOW()', 'edu.harvard.i2b2.crc', 1);` + "\n"

	_, err = DBi2b2DemodataPatientMapping.WriteString(hive)

	if err != nil {
		log.Fatal("Error in the writeDemodataPatientMapping()-Hive:", err)
		return err
	}

	return nil

}

// TODO: No dummy data. Basically all flags are
func writeDemodataPatientDimension(group *onet.Roster) error {

	encryptedFlag := lib.EncryptInt(group.Aggregate, 1)
	b := encryptedFlag.ToBytes()

	patientDimension := `INSERT INTO i2b2demodata.patient_dimension VALUES(` + strconv.FormatInt(PatientID, 10) + `, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'NOW()', NULL, 1, "` + base64.StdEncoding.EncodeToString(b) + `");` + "\n"

	_, err := DBi2b2DemodataPatientDimension.WriteString(patientDimension)

	if err != nil {
		log.Fatal("Error in the writeDemodataPatientDimension()-Hive:", err)
		return err
	}

	return nil
}

func writeDemodataEncounterMapping(sampleID, patientID string) error {

	encounterChuv := `INSERT INTO i2b2demodata.encounter_mapping VALUES ('` + sampleID + `', 'chuv', 'Demo', ` + strconv.FormatInt(EncounterID, 10) + `, '` + patientID + `', 'chuv', NULL, NULL, NULL, NULL, 'NOW()', NULL, 1);` + "\n"

	_, err := DBi2b2DemodataEncounterMapping.WriteString(encounterChuv)

	if err != nil {
		log.Fatal("Error in the writeDemodataEncounterMapping()-Chuv:", err)
		return err
	}

	encounterHive := `INSERT INTO i2b2demodata.encounter_mapping VALUES ('` + strconv.FormatInt(EncounterID, 10) + `', 'HIVE', 'HIVE', ` + strconv.FormatInt(EncounterID, 10) + `, '` + sampleID + `', 'chuv', 'A', NULL, 'NOW()', 'NOW()', 'NOW()', 'edu.harvard.i2b2.crc', 1);` + "\n"

	_, err = DBi2b2DemodataEncounterMapping.WriteString(encounterHive)

	if err != nil {
		log.Fatal("Error in the writeDemodataEncounterMapping()-Chuv:", err)
		return err
	}

	return nil
}

func writeDemodataVisitDimension() error {

	visit := `INSERT INTO i2b2demodata.visit_dimension VALUES (` + strconv.FormatInt(EncounterID, 10) + `, ` + strconv.FormatInt(PatientID, 10) + `, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'NOW()', 'chuv', 1);` + "\n"

	_, err := DBi2b2DemodataVisitDimension.WriteString(visit)

	if err != nil {
		log.Fatal("Error in the writeDemodataVisitDimension():", err)
		return err
	}

	return nil
}

func writeDemodataProviderDimension() error {

	provider := `INSERT INTO i2b2demodata.provider_dimension VALUES ('chuv', '\\medco\\institutions\\chuv\\', 'chuv', NULL, NULL, NULL, 'NOW()', NULL, 1);` + "\n"

	_, err := DBi2b2DemodataProviderDimension.WriteString(provider)

	if err != nil {
		log.Fatal("Error in the writeDemodateProviderDimension():", err)
		return err
	}

	return nil
}

func writeDemodataObservationFactClear(el int64) error {

	clear := `INSERT INTO i2b2demodata.observation_fact VALUES(` + strconv.FormatInt(PatientID, 10) + `, ` + strconv.FormatInt(EncounterID, 10) + `,
			'CLEAR:` + strconv.FormatInt(el, 10) + `', 'chuv', 'NOW()', '@', 1, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
			'chuv', NULL, NULL, NULL, NULL, 'NOW()', NULL, 1, 1);` + "\n"

	_, err := DBi2b2DemodataObservationFact.WriteString(clear)

	if err != nil {
		log.Fatal("Error in the writeDemodataObservationFactClear():", err)
		return err
	}

	return nil
}

func writeDemodataObservationFactEnc(el string, link PatientVisitLink) error {

	encrypted := `INSERT INTO i2b2demodata.observation_fact VALUES(` + strconv.FormatInt(link.PatientID, 10) + `, ` + strconv.FormatInt(link.EncounterID, 10) + `, 'TAG_ID:` + el + `',
			'chuv', 'NOW()', '@', 1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'chuv', NULL, NULL, NULL, NULL, 'NOW()', NULL, 1, 1);` + "\n"

	_, err := DBi2b2DemodataObservationFact.WriteString(encrypted)

	if err != nil {
		log.Fatal("Error in the writeDemodataObservationFactEnc():", err)
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
