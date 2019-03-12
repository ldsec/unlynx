package libunlynxtools_test

import (
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/dedis/kyber/util/key"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet/log"
	"github.com/lca1/unlynx/lib"
	. "github.com/lca1/unlynx/lib/tools"
	"github.com/stretchr/testify/assert"
)

const file = "pre_compute_multiplications.gob"
const k = 5

func TestWriteToGobFile(t *testing.T) {
	dataCipher := make([]libunlynx.CipherVectorScalar, 0)

	cipher := libunlynx.CipherVectorScalar{}

	v1 := libunlynx.SuiTe.Scalar().Pick(random.New())
	v2 := libunlynx.SuiTe.Scalar().Pick(random.New())

	cipher.S = append(cipher.S, v1, v2)

	vK := libunlynx.SuiTe.Point()
	vC := libunlynx.SuiTe.Point()

	ct := libunlynx.CipherText{K: vK, C: vC}

	cipher.CipherV = append(cipher.CipherV, ct)
	dataCipher = append(dataCipher, cipher)

	// we need bytes (or any other serializable data) to be able to store in a gob file
	encoded, err := EncodeCipherVectorScalar(dataCipher)

	if err != nil {
		log.Fatal("Error during marshling")
	}

	WriteToGobFile(file, encoded)
}

func TestReadFromGobFile(t *testing.T) {
	var encoded []libunlynx.CipherVectorScalarBytes

	ReadFromGobFile(file, &encoded)

	dataCipher, err := DecodeCipherVectorScalar(encoded)

	if err != nil {
		log.Fatal("Error during unmarshling")
	}

	fmt.Println(dataCipher)
	if err := os.Remove("pre_compute_multiplications.gob"); err != nil {
		log.Fatal("Error removing pre_compute_multiplications.gob file")
	}
}

func TestAddInMap(t *testing.T) {
	keys := key.NewKeyPair(libunlynx.SuiTe)
	_, pubKey := keys.Private, keys.Public
	gkey := libunlynx.GroupingKey("test")

	cv := make(libunlynx.CipherVector, k)
	for i := 0; i < k; i++ {
		cv[i] = *libunlynx.EncryptInt(pubKey, int64(i))
	}
	fr := libunlynx.FilteredResponse{GroupByEnc: cv, AggregatingAttributes: cv}

	mapToTest := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)
	_, ok := mapToTest[gkey]
	assert.False(t, ok)

	AddInMap(mapToTest, gkey, fr)
	v, ok2 := mapToTest[gkey]
	assert.True(t, ok2)
	assert.Equal(t, v, fr)
}

func TestInt64ArrayToString(t *testing.T) {
	toTest := make([]int64, k)
	for i := range toTest {
		toTest[i] = int64(i)
	}

	str := Int64ArrayToString(toTest)
	retVal := StringToInt64Array(str)

	assert.Equal(t, toTest, retVal)
}

func TestConvertDataToMap(t *testing.T) {
	toTest := make([]int64, k)
	for i := range toTest {
		toTest[i] = int64(i)
	}

	first := "test"
	start := 1
	mapRes := ConvertDataToMap(toTest, first, start)
	arrayRes := ConvertMapToData(mapRes, first, start)

	assert.Equal(t, toTest, arrayRes)
}

func TestFromDpClearResponseToProcess(t *testing.T) {
	keys := key.NewKeyPair(libunlynx.SuiTe)
	secKey, pubKey := keys.Private, keys.Public

	k := 5
	dpClearResponse := libunlynx.DpClearResponse{
		WhereClear:                 make(map[string]int64),
		WhereEnc:                   make(map[string]int64),
		GroupByClear:               make(map[string]int64),
		GroupByEnc:                 make(map[string]int64),
		AggregatingAttributesClear: make(map[string]int64),
		AggregatingAttributesEnc:   make(map[string]int64),
	}

	for i := 0; i < k; i++ {
		dpClearResponse.GroupByClear["g"+strconv.Itoa(i)] = int64(i)
		dpClearResponse.GroupByEnc["g"+strconv.Itoa(i+k)] = int64(i)
		dpClearResponse.WhereClear["w"+strconv.Itoa(i)] = int64(i)
		dpClearResponse.WhereEnc["w"+strconv.Itoa(i+k)] = int64(i)
		dpClearResponse.AggregatingAttributesClear["s"+strconv.Itoa(i)] = int64(i)
		dpClearResponse.AggregatingAttributesEnc["s"+strconv.Itoa(i+k)] = int64(i)
	}

	pr := FromDpClearResponseToProcess(&dpClearResponse, pubKey)

	for i := 0; i < k; i++ {
		pos := i
		v := dpClearResponse.GroupByClear["g"+strconv.Itoa(i)]
		assert.Equal(t, libunlynx.DecryptInt(secKey, pr.GroupByEnc[pos]), v)
		pos += len(dpClearResponse.GroupByClear)
		v = dpClearResponse.GroupByEnc["g"+strconv.Itoa(i+k)]
		assert.Equal(t, libunlynx.DecryptInt(secKey, pr.GroupByEnc[pos]), v)

		pos = i
		v = dpClearResponse.WhereClear["w"+strconv.Itoa(i)]
		assert.Equal(t, libunlynx.DecryptInt(secKey, pr.WhereEnc[pos]), v)
		pos += len(dpClearResponse.WhereClear)
		v = dpClearResponse.WhereEnc["w"+strconv.Itoa(i+k)]
		assert.Equal(t, libunlynx.DecryptInt(secKey, pr.WhereEnc[pos]), v)

		pos = i
		v = dpClearResponse.AggregatingAttributesClear["s"+strconv.Itoa(i)]
		assert.Equal(t, libunlynx.DecryptInt(secKey, pr.AggregatingAttributes[pos]), v)
		pos += len(dpClearResponse.AggregatingAttributesClear)
		v = dpClearResponse.AggregatingAttributesEnc["s"+strconv.Itoa(i+k)]
		assert.Equal(t, libunlynx.DecryptInt(secKey, pr.AggregatingAttributes[pos]), v)
	}
}
