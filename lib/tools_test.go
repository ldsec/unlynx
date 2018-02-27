package libunlynx

import (
	"fmt"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"os"
	"testing"
)

const file = "pre_compute_multiplications.gob"

func TestWriteToGobFile(t *testing.T) {
	dataCipher := make([]CipherVectorScalar, 0)

	cipher := CipherVectorScalar{}

	v1 := network.Suite.Scalar().Pick(random.Stream)
	v2 := network.Suite.Scalar().Pick(random.Stream)

	cipher.S = append(cipher.S, v1, v2)

	vK := network.Suite.Point()
	vC := network.Suite.Point()

	ct := CipherText{K: vK, C: vC}

	cipher.CipherV = append(cipher.CipherV, ct)
	dataCipher = append(dataCipher, cipher)

	// we need bytes (or any other serializable data) to be able to store in a gob file
	encoded, err := EncodeCipherVectorScalar(dataCipher)

	if err != nil {
		log.Fatal("Error during marshling")
	}

	WriteToGobFile(file, encoded)

	fmt.Println(dataCipher)
}

func TestReadFromGobFile(t *testing.T) {
	var encoded []CipherVectorScalarBytes

	ReadFromGobFile(file, &encoded)

	dataCipher, err := DecodeCipherVectorScalar(encoded)

	if err != nil {
		log.Fatal("Error during unmarshling")
	}

	fmt.Println(dataCipher)
	os.Remove("pre_compute_multiplications.gob")
}
