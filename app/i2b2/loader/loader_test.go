package loader_test

import (
	"github.com/lca1/unlynx/app/i2b2/loader"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"os"
	"testing"
	"gopkg.in/dedis/onet.v1/app"
)

const (
	CLINICAL_FILE = "files/data_clinical_skcm_broad.csv"
	GENOMIC_FILE  = "files/data_mutations_extended_skcm_broad.csv"
)

func getRoster(groupFilePath string) (*onet.Roster, error) {

	// empty string: make localtest
	if len(groupFilePath) == 0 {
		log.Info("Creating local test roster")

		local := onet.NewLocalTest()
		_, el, _ := local.GenTree(3, true)
		defer local.CloseAll()
		return el, nil

	// generate el with group file
	} else {
		log.Info("Creating roster from group file path")

		f, err := os.Open(groupFilePath)
		if err != nil {
			log.Error("Error while opening group file", err)
			return nil, err
		}
		el, err := app.ReadGroupToml(f)
		if err != nil {
			log.Error("Error while reading group file", err)
			return nil, err
		}
		if len(el.List) <= 0 {
			log.Error("Empty or invalid group file", err)
			return nil, err
		}

		return el, nil
	}
}

func generateDataFiles(t *testing.T, el *onet.Roster, entryPointIdx int) {
	log.SetDebugVisible(1)

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

	for _, f := range loader.FilePaths {
		fp, err := os.Create(f)
		assert.True(t, err == nil, err)
		loader.FileHandlers = append(loader.FileHandlers, fp)
	}

	listSensitive := make([]string, 0)
	listSensitive = append(listSensitive, "PRIMARY_TUMOR_LOCALIZATION_TYPE")
	listSensitive = append(listSensitive, "CANCER_TYPE_DETAILED")

	err = loader.GenerateDataFiles(el, entryPointIdx, fClinical, fGenomic, listSensitive)
	assert.True(t, err == nil, err)

	for _, f := range loader.FileHandlers {
		f.Close()
	}
}

func TestGenerateDataFilesLocalTest(t *testing.T) {
	el, err := getRoster("")
	assert.True(t, err == nil, err)
	generateDataFiles(t, el, 0)
}

func TestGenerateDataFilesGroupFile(t *testing.T) {
	// todo: fix hardcoded path
	el, err := getRoster("/home/misbach/repositories/medco-deployment/configuration/keys/dev-3nodes-samehost/group.toml")
	assert.True(t, err == nil, err)
	generateDataFiles(t, el, 0)
}

func TestReplayDataset(t *testing.T) {
	t.Skip()
	err := loader.ReplayDataset(GENOMIC_FILE, 2)
	assert.True(t, err == nil)
}

func TestGenerateLoadingScript(t *testing.T) {
	err := loader.GenerateLoadingScript()
	assert.True(t, err == nil)
}

func TestLoadDataFiles(t *testing.T) {
	t.Skip()
	err := loader.LoadDataFiles()
	assert.True(t, err == nil)
}