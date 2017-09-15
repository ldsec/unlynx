package loader_test

import (
	"github.com/lca1/unlynx/app/i2b2/loader"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/app"
	"gopkg.in/dedis/onet.v1/log"
	"os"
	"testing"
)

const (
	CLINICAL_ONTOLOGY = "files/data_clinical_skcm_broad.csv"
	GENOMIC_ONTOLOGY  = "files/data_mutations_extended_skcm_broad.csv"
	CLINICAL_FILE     = "files/data_clinical_skcm_broad_part1.csv"
	GENOMIC_FILE      = "files/data_mutations_extended_skcm_broad_part1.csv"
)

func getRoster(groupFilePath string) (*onet.Roster, *onet.LocalTest, error) {

	// empty string: make localtest
	if len(groupFilePath) == 0 {
		log.Info("Creating local test roster")

		local := onet.NewLocalTest()
		_, el, _ := local.GenTree(3, true)
		return el, local, nil

		// generate el with group file
	} else {
		log.Info("Creating roster from group file path")

		f, err := os.Open(groupFilePath)
		if err != nil {
			log.Error("Error while opening group file", err)
			return nil, nil, err
		}
		el, err := app.ReadGroupToml(f)
		if err != nil {
			log.Error("Error while reading group file", err)
			return nil, nil, err
		}
		if len(el.List) <= 0 {
			log.Error("Empty or invalid group file", err)
			return nil, nil, err
		}

		return el, nil, nil
	}
}

func generateFiles(t *testing.T, el *onet.Roster, entryPointIdx int) {
	log.SetDebugVisible(1)

	fOntologyClinical, err := os.Open(CLINICAL_ONTOLOGY)
	assert.True(t, err == nil, err)
	fOntologyGenomic, err := os.Open(GENOMIC_ONTOLOGY)
	assert.True(t, err == nil, err)

	fClinical, err := os.Open(CLINICAL_FILE)
	assert.True(t, err == nil, err)
	fGenomic, err := os.Open(GENOMIC_FILE)
	assert.True(t, err == nil, err)

	// init global variables
	loader.FileHandlers = make([]*os.File, 0)
	loader.Testing = true
	loader.OntValues = make(map[loader.ConceptPath]loader.ConceptID)
	loader.TextSearchIndex = int64(1)

	for _, f := range loader.FilePaths {
		fp, err := os.Create(f)
		assert.True(t, err == nil, err)
		loader.FileHandlers = append(loader.FileHandlers, fp)
	}

	listSensitive := make([]string, 0)
	listSensitive = append(listSensitive, "PRIMARY_TUMOR_LOCALIZATION_TYPE")
	listSensitive = append(listSensitive, "CANCER_TYPE_DETAILED")

	err = loader.GenerateOntologyFiles(el, entryPointIdx, fOntologyClinical, fOntologyGenomic, listSensitive)
	assert.True(t, err == nil, err)

	err = loader.GenerateDataFiles(el, fClinical, fGenomic)
	assert.True(t, err == nil, err)

	for _, f := range loader.FileHandlers {
		f.Close()
	}

	fClinical.Close()
	fGenomic.Close()

	fOntologyClinical.Close()
	fOntologyGenomic.Close()
}

func TestGenerateFilesLocalTest(t *testing.T) {
	el, local, err := getRoster("")
	assert.True(t, err == nil, err)
	generateFiles(t, el, 0)
	local.CloseAll()
}

func TestGenerateFilesGroupFile(t *testing.T) {
	//t.Skip()
	// todo: fix hardcoded path
	el, _, err := getRoster("/Users/jagomes/Documents/EPFL/MedCo/i2b2/medco-deployment/configuration/keys/dev-3nodes-samehost/group.toml")
	assert.True(t, err == nil, err)
	generateFiles(t, el, 0)
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
