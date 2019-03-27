package libunlynxtools_test

import (
	"testing"

	. "github.com/lca1/unlynx/lib/tools"
	"github.com/stretchr/testify/assert"
)

func TestInt64ArrayToString(t *testing.T) {
	toTest := make([]int64, 5)
	for i := range toTest {
		toTest[i] = int64(i)
	}

	str := Int64ArrayToString(toTest)
	retVal := StringToInt64Array(str)

	assert.Equal(t, toTest, retVal)
}

func TestConvertDataToMap(t *testing.T) {
	toTest := make([]int64, 5)
	for i := range toTest {
		toTest[i] = int64(i)
	}

	first := "test"
	start := 1
	mapRes := ConvertDataToMap(toTest, first, start)
	arrayRes := ConvertMapToData(mapRes, first, start)

	assert.Equal(t, toTest, arrayRes)
}
