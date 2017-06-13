package services_test

import (
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/services"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
	"os"
	"strconv"
	"testing"
)

func TestPrecomputationWritingForShuffling(t *testing.T) {
	os.Remove("pre_compute_multiplications.gob")
	local := onet.NewLocalTest()
	_, el, _ := local.GenTree(3, true)
	defer local.CloseAll()

	lineSize := 10
	secret := network.Suite.Scalar().Pick(random.Stream)

	precompute := services.PrecomputationWritingForShuffling(false, "pre_compute_multiplications.gob", "test_server", secret, el.Aggregate, lineSize)
	assert.Equal(t, len(precompute), lineSize)

	// writes precomputation file
	precompute = services.PrecomputationWritingForShuffling(true, "pre_compute_multiplications.gob", "test_server", secret, el.Aggregate, lineSize)
	assert.Equal(t, len(precompute), lineSize)

	// reads precomputation file
	precompute = services.ReadPrecomputedFile("pre_compute_multiplications.gob")
	assert.Equal(t, len(precompute), lineSize)

}

func TestFilterResponses(t *testing.T) {
	// ****************************************
	// simple predicate
	predicate := "v0 == v1"

	whereAttributes := make([]lib.WhereQueryAttributeTagged, 0)
	whereAttributes = append(whereAttributes, lib.WhereQueryAttributeTagged{Name: "w0", Value: "1"})

	data := make([]lib.ProcessResponseDet, 0)

	// predicate is true
	whereTrue := [1]lib.GroupingKey{lib.GroupingKey("1")}

	// predicate is false
	whereFalse := [1]lib.GroupingKey{lib.GroupingKey("0")}

	data = append(data, lib.ProcessResponseDet{PR: lib.ProcessResponse{}, DetTagGroupBy: "", DetTagWhere: whereTrue[:]})
	data = append(data, lib.ProcessResponseDet{PR: lib.ProcessResponse{}, DetTagGroupBy: "", DetTagWhere: whereFalse[:]})

	result := services.FilterResponses(predicate, whereAttributes, data)

	// 1 result(s) are true
	assert.Equal(t, len(result), 1)

	data = append(data, lib.ProcessResponseDet{PR: lib.ProcessResponse{}, DetTagGroupBy: "", DetTagWhere: whereTrue[:]})

	result = services.FilterResponses(predicate, whereAttributes, data)

	// 2 result(s) are true
	assert.Equal(t, len(result), 2)

	// ****************************************
	// more complex predicate
	predicate = "v0 != v1 || (v2 == v3 && v4 == v5)"

	whereAttributes = make([]lib.WhereQueryAttributeTagged, 0)
	whereAttributes = append(whereAttributes, lib.WhereQueryAttributeTagged{Name: "w0", Value: "27"})
	whereAttributes = append(whereAttributes, lib.WhereQueryAttributeTagged{Name: "w1", Value: "0"})
	whereAttributes = append(whereAttributes, lib.WhereQueryAttributeTagged{Name: "w2", Value: "99"})

	// predicate is true
	whereTrue1 := [3]lib.GroupingKey{lib.GroupingKey("21"), lib.GroupingKey("6"), lib.GroupingKey("0")}
	whereTrue2 := [3]lib.GroupingKey{lib.GroupingKey("27"), lib.GroupingKey("0"), lib.GroupingKey("99")}

	// predicate is false
	whereFalse1 := [3]lib.GroupingKey{lib.GroupingKey("27"), lib.GroupingKey("6"), lib.GroupingKey("0")}

	data = make([]lib.ProcessResponseDet, 0)
	data = append(data, lib.ProcessResponseDet{PR: lib.ProcessResponse{}, DetTagGroupBy: "", DetTagWhere: whereTrue1[:]})
	data = append(data, lib.ProcessResponseDet{PR: lib.ProcessResponse{}, DetTagGroupBy: "", DetTagWhere: whereTrue2[:]})
	data = append(data, lib.ProcessResponseDet{PR: lib.ProcessResponse{}, DetTagGroupBy: "", DetTagWhere: whereFalse1[:]})

	result = services.FilterResponses(predicate, whereAttributes, data)

	// 2 result(s) are true
	assert.Equal(t, len(result), 2)
}

func TestCountDPs(t *testing.T) {
	nbrServer := 7
	nbrElementsPerServer := 3

	mapTest := make(map[string]int64)
	for i := 0; i < nbrServer; i++ {
		mapTest["server"+strconv.Itoa(i)] = int64(nbrElementsPerServer)
	}

	assert.Equal(t, int64(nbrElementsPerServer*nbrServer), services.CountDPs(mapTest))
}
