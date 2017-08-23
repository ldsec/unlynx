package loader_test

import (
	"github.com/lca1/unlynx/app/i2b2/loader"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/onet.v1/log"
	"os"
	"testing"
)

const (
	CLINICAL_FILE = "files/data_clinical_skcm_broad.csv"
	GENOMIC_FILE  = "files/data_mutations_extended_skcm_broad.csv"
)

func TestLoadDataFiles(t *testing.T) {

	fClinical, err := os.Open(CLINICAL_FILE)
	if err != nil {
		log.Fatal("Error while opening the clinical file", err)
	}

	fGenomic, err := os.Open(GENOMIC_FILE)
	if err != nil {
		log.Fatal("Error while opening the genomic file", err)
	}

	err = loader.InitFiles()
	assert.True(t, err == nil)

	err = loader.LoadDataFiles(fClinical, fGenomic)
	assert.True(t, err == nil, err)

	loader.CloseFiles()
}
