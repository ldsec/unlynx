package libunlynxshuffle_test

import (
	"os"
	"testing"

	"github.com/ldsec/unlynx/lib"
	"github.com/ldsec/unlynx/lib/shuffle"
	"github.com/ldsec/unlynx/lib/tools"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3"
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

	precompute, err := libunlynxshuffle.PrecomputationWritingForShuffling(false, "pre_compute_multiplications.gob", "test_server", secret, el.Aggregate, lineSize)
	assert.NoError(t, err)
	assert.Equal(t, len(precompute), lineSize)

	// writes precomputation file
	precompute, err = libunlynxshuffle.PrecomputationWritingForShuffling(true, "pre_compute_multiplications.gob", "test_server", secret, el.Aggregate, lineSize)
	assert.NoError(t, err)
	assert.Equal(t, len(precompute), lineSize)

	// reads precomputation file
	precompute, err = libunlynxshuffle.ReadPrecomputedFile("pre_compute_multiplications.gob")
	assert.NoError(t, err)
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
	assert.NoError(t, err)
	err = libunlynxtools.WriteToGobFile(file, encoded)
	assert.NoError(t, err)
}

func TestReadFromGobFile(t *testing.T) {
	var encoded []libunlynxshuffle.CipherVectorScalarBytes
	err := libunlynxtools.ReadFromGobFile(file, &encoded)
	assert.NoError(t, err)

	_, err = libunlynxshuffle.DecodeCipherVectorScalar(encoded)
	assert.NoError(t, err)

	_ = os.Remove("pre_compute_multiplications.gob")
}
