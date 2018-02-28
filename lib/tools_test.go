package libunlynx_test

import (
	"fmt"
	"gopkg.in/dedis/onet.v1/log"
	"os"
	"testing"
	"github.com/dedis/kyber/util/random"
	"github.com/lca1/unlynx/lib"
)

const file = "pre_compute_multiplications.gob"

func TestWriteToGobFile(t *testing.T) {
	dataCipher := make([]libunlynx.CipherVectorScalar, 0)

	cipher := libunlynx.CipherVectorScalar{}

	v1 := libunlynx.SuiteT.Scalar().Pick(random.New())
	v2 := libunlynx.SuiteT.Scalar().Pick(random.New())

	cipher.S = append(cipher.S, v1, v2)

	vK := libunlynx.SuiteT.Point()
	vC := libunlynx.SuiteT.Point()

	ct := libunlynx.CipherText{K: vK, C: vC}

	cipher.CipherV = append(cipher.CipherV, ct)
	dataCipher = append(dataCipher, cipher)

	// we need bytes (or any other serializable data) to be able to store in a gob file
	encoded, err := libunlynx.EncodeCipherVectorScalar(dataCipher)

	if err != nil {
		log.Fatal("Error during marshling")
	}

	libunlynx.WriteToGobFile(file, encoded)

	fmt.Println(dataCipher)
}

func TestReadFromGobFile(t *testing.T) {
	var encoded []libunlynx.CipherVectorScalarBytes

	libunlynx.ReadFromGobFile(file, &encoded)

	dataCipher, err := libunlynx.DecodeCipherVectorScalar(encoded)

	if err != nil {
		log.Fatal("Error during unmarshling")
	}

	fmt.Println(dataCipher)
	os.Remove("pre_compute_multiplications.gob")
}
