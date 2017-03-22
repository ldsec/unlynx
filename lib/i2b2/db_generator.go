package libi2b2

/*
import (
	"database/sql"
	"encoding/hex"
	"strconv"

	"gopkg.in/dedis/onet.v1/network"

	"github.com/JoaoAndreSa/MedCo/lib"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1/crypto"
	"gopkg.in/dedis/onet.v1/log"
	"strings"
)

// ValueGetter is a struct pemitting to store values from ValueGetterCol
type ValueGetter struct {
	Others       interface{}
	ConceptCd    string
	EncounterNum string
	PatientNum   string
	ProviderID   string
	StartDate    string
	ModifierCd   string
	InstanceNum  string
	Age          string
	Zip          string
}

// valueGetterCol allows to get value from chosencolumns
func valueGetterCol(colname string, vg *ValueGetter) interface{} {
	switch colname {
	case "encounter_num":
		return &vg.EncounterNum
	case "patient_num":
		return &vg.PatientNum
	case "provider_id":
		return &vg.ProviderID
	case "start_date":
		return &vg.StartDate
	case "modifier_cd":
		return &vg.ModifierCd
	case "instance_num":
		return &vg.InstanceNum
	case "concept_cd":
		return &vg.ConceptCd
	case "age_in_years_num":
		return &vg.Age
	case "zip_cd":
		return &vg.Zip
	default:
		return &vg.Others
	}
}

// CreateDatabaseConcept permits to create an encrypted version of the observation_fact table in i2b2
// This method is a first step towards this direction, its use is not optimized and very specific
func CreateDatabaseConcept(maxSensitive int, pubKeyString string, delete bool, onlyTestString string) {
	//get public key from string
	pubKey, err := crypto.ReadHexPub(network.Suite, strings.NewReader(pubKeyString))
	checkErr(err)
	onlyTest, err := crypto.ReadHexScalar(network.Suite, strings.NewReader(onlyTestString))
	checkErr(err)

	//access database
	db, err := sql.Open("postgres", "user=froelicher dbname=i2b2-medco host=icsil1noteb206.epfl.ch password=froelicher port=15432")
	checkErr(err)
	err = db.Ping()
	if err != nil {
		log.Error("Ping issue: ", err)
	}
	defer db.Close()

	//if database needs to be cleaned
	if delete {
		q1, err := db.Query("DROP TABLE i2b2demodata.observation_factTest")
		checkErr(err)
		q1.Close()
		q1, err = db.Query("DROP TABLE i2b2demodata.observation_factTest_clear")
		checkErr(err)
		q1.Close()
		q1, err = db.Query("CREATE TABLE i2b2demodata.observation_factTest AS SELECT * FROM i2b2demodata.observation_fact WHERE concept_cd = 'LOINC:2823-3' OR concept_cd = 'LOINC:2885-2'")
		checkErr(err)
		q1.Close()
		q1, err = db.Query("DROP TABLE i2b2demodata.observation_factTest_enc")
		checkErr(err)
		closeRequest(q1)
		q1, err = db.Query("DROP TABLE i2b2demodata.enc_observations")
		checkErr(err)
		closeRequest(q1)
	}
	//initiate a counter to limit the number of observations categorized as sensitive (randomly chosen for now)
	counter := 0

	//query complete table
	rowsGen, err := db.Query("SELECT * FROM i2b2demodata.observation_factTest")
	checkErr(err)

	//save sensitive observations in a slice
	encryptedObs := make([]string, 0)

	//loop on table
	first := true
	colNums := 0
	colNames := []string{}
	for rowsGen.Next() {
		if first {
			//first line
			colNames, err = rowsGen.Columns()
			first = false
			log.LLvl1("Read first line")
			colNums = len(colNames)

		}
		//get useful columns data
		vgGen := ValueGetter{}
		cols := make([]interface{}, colNums)
		for i := 0; i < colNums; i++ {
			cols[i] = valueGetterCol(colNames[i], &vgGen)
		}
		err = rowsGen.Scan(cols...)
		checkErr(err)

		//check if column already created for this observation
		present := false
		for _, v := range colNames {
			if v == vgGen.ConceptCd {
				present = true
				log.LLvl1("Observation already classified as sensitive")
			}
		}

		observation := vgGen.ConceptCd
		checkCount := 0
		log.LLvl1("Processing: " + observation)
		if observation != "e" {
			//if observation not already processed
			if present {
				//if observation already has a dedicated column
				encryptedOne := hex.EncodeToString((*lib.EncryptInt(pubKey, 1)).ToBytes())
				q3, err := db.Query("UPDATE i2b2demodata.observation_facttest SET \"" + observation + "\"='" + encryptedOne + "' WHERE encounter_num=" + string(vgGen.EncounterNum) + " AND patient_num=" + string(vgGen.PatientNum) + " AND concept_cd='" + observation + "' AND provider_id='" + vgGen.ProviderID + "' AND start_date='" + vgGen.StartDate + "' AND modifier_cd='" + vgGen.ModifierCd + "' AND instance_num=" + string(vgGen.InstanceNum))
				checkErr(err)
				closeRequest(q3)
			}
			if !present && (counter < maxSensitive) {
				//if observation does not already have a dedicated column
				encryptedObs = append(encryptedObs, observation)

				//create column
				q2, err := db.Query("ALTER TABLE i2b2demodata.observation_facttest ADD \"" + vgGen.ConceptCd + "\"  varchar(200) NULL;")
				checkErr(err)
				closeRequest(q2)

				//loop on all lines
				rows, err := db.Query("SELECT * FROM i2b2demodata.observation_facttest")
				checkErr(err)
				for rows.Next() {
					colNames1, err := rows.Columns()
					colNames = colNames1
					checkErr(err)
					colNums1 := len(colNames1)
					vg := ValueGetter{}
					cols := make([]interface{}, colNums1)
					for i := 0; i < colNums1; i++ {
						cols[i] = valueGetterCol(colNames1[i], &vg)
					}

					err = rows.Scan(cols...)
					//for all lines with a different ConceptCd -> encrypt a ZERO
					if vg.ConceptCd != observation {
						log.LLvl1("ZERO encryption")
						encryptedZero := hex.EncodeToString((*lib.EncryptInt(pubKey, 0)).ToBytes())
						q3, err := db.Query("UPDATE i2b2demodata.observation_facttest SET \"" + observation + "\"='" + encryptedZero + "' WHERE encounter_num=" + string(vg.EncounterNum) + " AND patient_num=" + string(vg.PatientNum) + " AND concept_cd='" + vg.ConceptCd + "' AND provider_id='" + vg.ProviderID + "' AND start_date='" + vg.StartDate + "' AND modifier_cd='" + vg.ModifierCd + "' AND instance_num=" + string(vg.InstanceNum))
						checkErr(err)
						closeRequest(q3)
					} else {
						//for all lines with same ConceptCd -> encrypt a ONE
						encryptedOne := hex.EncodeToString((*lib.EncryptInt(pubKey, 1)).ToBytes())
						log.LLvl1("ONE encryption")
						q3, err := db.Query("UPDATE i2b2demodata.observation_facttest SET \"" + observation + "\"='" + encryptedOne + "' WHERE encounter_num=" + string(vgGen.EncounterNum) + " AND patient_num=" + string(vgGen.PatientNum) + " AND concept_cd='" + observation + "' AND provider_id='" + vgGen.ProviderID + "' AND start_date='" + vgGen.StartDate + "' AND modifier_cd='" + vgGen.ModifierCd + "' AND instance_num=" + string(vgGen.InstanceNum))
						checkErr(err)
						closeRequest(q3)
					}
					checkCount++
					if checkCount%10 == 0 {
						log.LLvl1(checkCount)
					}

				}
				closeRequest(rows)

				counter++
			}
		}
	}
	closeRequest(rowsGen)

	//replace all encrypted observations by 'e'
	//create a list of sensitive observations in i2b2demodata.enc_observations
	_, err = db.Query("CREATE TABLE i2b2demodata.enc_observations(observations char(100))")
	checkErr(err)
	for _, s := range encryptedObs {
		q5, err := db.Query("UPDATE i2b2demodata.observation_facttest SET concept_cd='e'  WHERE concept_cd='" + s + "'")
		checkErr(err)
		closeRequest(q5)
		q5, err = db.Query("INSERT INTO i2b2demodata.enc_observations VALUES ('" + s + "')")
		checkErr(err)
		closeRequest(q5)
	}

	//create encrypted table of observations
	q6, err := db.Query("CREATE TABLE i2b2demodata.observation_facttest_enc as SELECT * FROM i2b2demodata.observation_facttest WHERE concept_cd='e'")
	checkErr(err)
	closeRequest(q6)
	q6, err = db.Query("ALTER TABLE i2b2demodata.observation_facttest_enc DROP COLUMN concept_cd")
	checkErr(err)
	closeRequest(q6)

	//remove sensitive values from normal observations table
	q6, err = db.Query("DELETE FROM i2b2demodata.observation_facttest WHERE concept_cd='e'")
	checkErr(err)
	closeRequest(q6)
	for _, s := range encryptedObs {
		q7, err := db.Query("ALTER TABLE i2b2demodata.observation_facttest DROP COLUMN \"" + s + "\"")
		checkErr(err)
		closeRequest(q7)
	}

	//for testing purposes, create a table of clear observations without two specific ontology terms
	q6, err = db.Query("CREATE TABLE i2b2demodata.observation_facttest_clear as SELECT * FROM i2b2demodata.observation_fact WHERE concept_cd != 'LOINC:2823-3' OR concept_cd != 'LOINC:2885-2'")
	checkErr(err)
	closeRequest(q6)

	// TEST IF encryption looks good
	qTest := db.QueryRow("Select \"LOINC:2823-3\" FROM i2b2demodata.observation_facttest_enc WHERE encounter_num=483534")
	result := ""
	qTest.Scan(&result)
	log.LLvl1(result)
	resultBytes, err := hex.DecodeString(result)
	checkErr(err)
	log.LLvl1(resultBytes)

	ct := lib.CipherText{}
	ct.FromBytes(resultBytes)
	log.LLvl1(ct)
	log.LLvl1(lib.DecryptInt(onlyTest, ct))

	qTest = db.QueryRow("Select \"LOINC:2885-2\" FROM i2b2demodata.observation_facttest_enc WHERE encounter_num=483534")
	qTest.Scan(&result)
	log.LLvl1(result)
	resultBytes, err = hex.DecodeString(result)
	checkErr(err)
	log.LLvl1(resultBytes)

	ct.FromBytes(resultBytes)
	log.LLvl1(ct)
	log.LLvl1(lib.DecryptInt(onlyTest, ct))

}

// CreateDatabasePatient permits to create a patient_dimension table with encrypted information (not used yet)
func CreateDatabasePatient(pubKey abstract.Point) {
	//database access
	db, err := sql.Open("postgres", "user=froelicher dbname=i2b2-medco host=icsil1noteb206.epfl.ch password=froelicher port=15432")
	checkErr(err)
	err = db.Ping()
	if err != nil {
		log.LLvl1("No ping")
		log.Fatal("Ping issue: " + err.Error())
	}
	defer db.Close()

	_, err = db.Query("ALTER TABLE i2b2demodata.patient_dimensionTest ADD age_in_years_en  varchar(200) NULL")
	checkErr(err)
	_, err = db.Query("ALTER TABLE i2b2demodata.patient_dimensionTest ADD zip_cd_en  varchar(200) NULL")
	checkErr(err)
	//loop on all lines
	rowsGen, err := db.Query("SELECT * FROM i2b2demodata.patient_dimensionTest")
	checkErr(err)
	for rowsGen.Next() {
		colNames, _ := rowsGen.Columns()
		colNums := len(colNames)
		vgGen := ValueGetter{}
		cols := make([]interface{}, colNums)
		for i := 0; i < colNums; i++ {
			cols[i] = valueGetterCol(colNames[i], &vgGen)
		}

		err = rowsGen.Scan(cols...)
		rowsGen.Scan(cols...)

		//encrypt age and zip columns
		age, _ := strconv.ParseInt(vgGen.Age, 10, 64)
		zip := vgGen.Zip
		zip1, _ := strconv.ParseInt(zip, 10, 64)

		encryptedAge := hex.EncodeToString((*lib.EncryptInt(pubKey, age)).ToBytes())
		encryptedZip := hex.EncodeToString((*lib.EncryptInt(pubKey, zip1)).ToBytes())
		_, err = db.Query("UPDATE i2b2demodata.patient_dimensionTest SET age_in_years_en='" + encryptedAge + "' , zip_cd_en='" + encryptedZip + "' WHERE patient_num=" + string(vgGen.PatientNum))

	}
	//rm too sensitive columns, unencryptable for now
	_, err = db.Query("ALTER TABLE i2b2demodata.patient_dimensionTest DROP COLUMN zip_cd")
	_, err = db.Query("ALTER TABLE i2b2demodata.patient_dimensionTest DROP COLUMN birth_date")
	_, err = db.Query("ALTER TABLE i2b2demodata.patient_dimensionTest DROP COLUMN age_in_years_num")
	_, err = db.Query("ALTER TABLE i2b2demodata.patient_dimensionTest DROP COLUMN statecityzip_path")
}

// checkErr displays an error message if the error is not nil
func checkErr(err error) {
	if err != nil {
		log.Fatal("error: " + err.Error())
	}
}

// close closes a request if not nil
func closeRequest(r *sql.Rows) {
	if r != nil {
		r.Close()
	}
}
*/
