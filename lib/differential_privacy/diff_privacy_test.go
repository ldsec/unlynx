package libunlynxdiffprivacy_test

import (
	"testing"

	. "github.com/lca1/unlynx/lib/differential_privacy"
	"github.com/stretchr/testify/assert"
)

// TestAddRmProof tests the generation of the noise values for the differential privacy
func TestGenerateNoiseValues(t *testing.T) {
	aux := GenerateNoiseValues(0, 0, 1, 0.005)
	assert.Empty(t, aux)

	aux = GenerateNoiseValues(500, 0, 1, 0.005)

	assert.Equal(t, len(aux), 500)

	temp := make([]float64, 0)
	for i := 0; i < 100; i++ {
		temp = append(temp, 0)
	}

	assert.Equal(t, temp, aux[:100])

	temp = make([]float64, 0)
	for i := 0; i < 19; i++ {
		temp = append(temp, 1)
		temp = append(temp, -1)
	}

	assert.Equal(t, temp, aux[100:138])
}
