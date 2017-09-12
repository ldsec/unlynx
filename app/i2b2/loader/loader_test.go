package loader_test

import (
	"github.com/lca1/unlynx/app/i2b2/loader"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"os"
	"testing"
)

const (
	CLINICAL_FILE = "files/data_clinical_skcm_broad.csv"
	GENOMIC_FILE  = "files/data_mutations_extended_skcm_broad.csv"
)

func TestGenerateDataFiles(t *testing.T) {
	log.SetDebugVisible(1)
	local := onet.NewLocalTest()
	_, el, _ := local.GenTree(3, true)
	defer local.CloseAll()

	fClinical, err := os.Open(CLINICAL_FILE)
	if err != nil {
		log.Fatal("Error while opening the clinical file", err)
	}

	fGenomic, err := os.Open(GENOMIC_FILE)
	if err != nil {
		log.Fatal("Error while opening the genomic file", err)
	}

	loader.EncID = int64(1)
	loader.ClearID = int64(1)
	loader.EncounterMapping = make(map[string]int64)
	loader.PatientMapping = make(map[string]int64)
	loader.AllSensitiveIDs = make([]int64, 0)
	loader.FileHandlers = make([]*os.File, 0)
	loader.TextSearchIndex = int64(1)
	loader.Testing = true

	for _, f := range loader.FilePaths {
		fp, err := os.Create(f)
		assert.True(t, err == nil, err)
		loader.FileHandlers = append(loader.FileHandlers, fp)
	}

	listSensitive := make([]string, 0)
	listSensitive = append(listSensitive, "PRIMARY_TUMOR_LOCALIZATION_TYPE")
	listSensitive = append(listSensitive, "CANCER_TYPE_DETAILED")

	err = loader.GenerateDataFiles(el, 0, fClinical, fGenomic, listSensitive)
	assert.True(t, err == nil, err)

	for _, f := range loader.FileHandlers {
		f.Close()
	}
}

func TestReplayDataset(t *testing.T) {
	t.Skip()
	err := loader.ReplayDataset(GENOMIC_FILE, 2)
	assert.True(t, err == nil)
}

func TestGenerateLoadingScript(t *testing.T) {
	err := loader.GenerateLoadingScript(loader.DBSettings{DBhost: "localhost", DBport: 5434, DBname: "medcodeployment", DBuser: "postgres", DBpassword: "prigen2017"})
	assert.True(t, err == nil)
}

func TestLoadDataFiles(t *testing.T) {
	t.Skip()
	err := loader.LoadDataFiles()
	assert.True(t, err == nil)
}
