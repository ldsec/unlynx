package libunlynxshuffle_test

import (
	"os"
	"testing"

	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/shuffle"
	"github.com/lca1/unlynx/lib/tools"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

func TestShuffleSequence(t *testing.T) {
	// number of responses
	k := 10

	collectivePubKey, priv, _ := libunlynx.GenKeys(k)
	collectivePrivKey := libunlynx.SuiTe.Scalar()

	for i := 0; i < len(priv); i++ {
		collectivePrivKey = libunlynx.SuiTe.Scalar().Add(collectivePrivKey, priv[i])
	}

	inputList := make([]libunlynx.CipherVector, k)

	for i := 0; i < k; i++ {
		inputList[i] = make(libunlynx.CipherVector, k)

		for ii := range inputList[i] {
			inputList[i][ii] = *libunlynx.EncryptInt(collectivePubKey, int64(i+1))
		}

	}
	outputlist, pi, _ := libunlynxshuffle.ShuffleSequence(inputList, libunlynx.SuiTe.Point().Base(), collectivePubKey, nil)

	piinv := make([]int, k)
	for i := 0; i < k; i++ {
		piinv[pi[i]] = i
	}

	for i := 0; i < k; i++ {
		for iii := range inputList[0] {
			decrypted := libunlynx.DecryptInt(collectivePrivKey, outputlist[piinv[i]][iii])
			assert.Equal(t, int64(i+1), decrypted)
		}
	}

}

func TestPrecomputationWritingForShuffling(t *testing.T) {
	local := onet.NewLocalTest(libunlynx.SuiTe)
	_, el, _ := local.GenTree(3, true)
	defer local.CloseAll()

	lineSize := 10
	secret := libunlynx.SuiTe.Scalar().Pick(random.New())

	precompute := libunlynxshuffle.PrecomputationWritingForShuffling(false, "pre_compute_multiplications.gob", "test_server", secret, el.Aggregate, lineSize)
	assert.Equal(t, len(precompute), lineSize)

	// writes precomputation file
	precompute = libunlynxshuffle.PrecomputationWritingForShuffling(true, "pre_compute_multiplications.gob", "test_server", secret, el.Aggregate, lineSize)
	assert.Equal(t, len(precompute), lineSize)

	// reads precomputation file
	precompute = libunlynxshuffle.ReadPrecomputedFile("pre_compute_multiplications.gob")
	assert.Equal(t, len(precompute), lineSize)

}

const file = "pre_compute_multiplications.gob"

func TestWriteToGobFile(t *testing.T) {
	dataCipher := make([]libunlynxshuffle.CipherVectorScalar, 0)

	cipher := libunlynxshuffle.CipherVectorScalar{}

	v1 := libunlynx.SuiTe.Scalar().Pick(random.New())
	v2 := libunlynx.SuiTe.Scalar().Pick(random.New())

	cipher.S = append(cipher.S, v1, v2)

	vK := libunlynx.SuiTe.Point()
	vC := libunlynx.SuiTe.Point()

	ct := libunlynx.CipherText{K: vK, C: vC}

	cipher.CipherV = append(cipher.CipherV, ct)
	dataCipher = append(dataCipher, cipher)

	// we need bytes (or any other serializable data) to be able to store in a gob file
	encoded, err := libunlynxshuffle.EncodeCipherVectorScalar(dataCipher)

	if err != nil {
		log.Fatal(err)
	}

	libunlynxtools.WriteToGobFile(file, encoded)
}

func TestReadFromGobFile(t *testing.T) {
	var encoded []libunlynxshuffle.CipherVectorScalarBytes

	libunlynxtools.ReadFromGobFile(file, &encoded)

	_, err := libunlynxshuffle.DecodeCipherVectorScalar(encoded)

	if err != nil {
		log.Fatal(err)
	}

	if err := os.Remove("pre_compute_multiplications.gob"); err != nil {
		log.Fatal("Error removing pre_compute_multiplications.gob file:", err)
	}
}
