package libunlynxtools_test

import (
	"github.com/lca1/unlynx/lib/tools"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInt64ArrayToString(t *testing.T) {
	toTest := make([]int64, 5)
	for i := range toTest {
		toTest[i] = int64(i)
	}

	str := libunlynxtools.Int64ArrayToString(toTest)
	retVal := libunlynxtools.StringToInt64Array(str)

	assert.Equal(t, toTest, retVal)
}

func TestConvertDataToMap(t *testing.T) {
	toTest := make([]int64, 5)
	for i := range toTest {
		toTest[i] = int64(i)
	}

	first := "test"
	start := 1
	mapRes := libunlynxtools.ConvertDataToMap(toTest, first, start)
	arrayRes := libunlynxtools.ConvertMapToData(mapRes, first, start)

	assert.Equal(t, toTest, arrayRes)
}
