package data_test

import (
	"fmt"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/services/data"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"os"
	"testing"
)

const file = "pre_compute_multiplications.gob"

func TestWriteToGobFile(t *testing.T) {
	data_cipher := make([]lib.CipherVectorScalar, 0)

	cipher := lib.CipherVectorScalar{}

	v1 := network.Suite.Scalar().Pick(random.Stream)
	v2 := network.Suite.Scalar().Pick(random.Stream)

	cipher.S = append(cipher.S, v1, v2)

	vK := network.Suite.Point()
	vC := network.Suite.Point()

	ct := lib.CipherText{K: vK, C: vC}

	cipher.CipherV = append(cipher.CipherV, ct)
	data_cipher = append(data_cipher, cipher)

	// we need bytes (or any other serializable data) to be able to store in a gob file
	encoded, err := data.EncodeCipherVectorScalar(data_cipher)

	if err != nil {
		log.Fatal("Error during marshling")
	}

	data.WriteToGobFile(file, encoded)

	fmt.Println(data_cipher)
}

func TestReadFromGobFile(t *testing.T) {
	var encoded []lib.CipherVectorScalarBytes

	data.ReadFromGobFile(file, &encoded)

	data_cipher, err := data.DecodeCipherVectorScalar(encoded)

	if err != nil {
		log.Fatal("Error during unmarshling")
	}

	fmt.Println(data_cipher)
	os.Remove("pre_compute_multiplications.gob")
}
