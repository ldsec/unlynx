package protocols_test

import (
	"testing"
	"time"

	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/protocols"
	"github.com/lca1/unlynx/services/data"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
)

func TestLocalClearAggregation(t *testing.T) {
	local := onet.NewLocalTest()
	_, _, tree := local.GenTree(1, true)

	defer local.CloseAll()

	rootInstance, err := local.CreateProtocol("LocalClearAggregation", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}
	protocol := rootInstance.(*protocols.LocalClearAggregationProtocol)

	testData := generateClearData()
	aggregatedData := lib.AddInClear(testData)

	protocol.TargetOfAggregation = testData
	feedback := protocol.FeedbackChannel

	go protocol.Start()

	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond

	select {
	case results := <-feedback:
		assert.Equal(t, data.CompareClearResponses(results, aggregatedData), true)
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}
}

func generateClearData() []lib.DpClearResponse {
	testData := make([]lib.DpClearResponse, 6)

	testData[0] = lib.DpClearResponse{WhereClear: lib.ConvertDataToMap([]int64{1, 1}, "w", 0), GroupByClear: lib.ConvertDataToMap([]int64{1, 1}, "g", 0), AggregatingAttributesClear: lib.ConvertDataToMap([]int64{1, 2, 3, 4, 5}, "s", 0)}
	testData[1] = lib.DpClearResponse{WhereClear: lib.ConvertDataToMap([]int64{1, 2}, "w", 0), GroupByClear: lib.ConvertDataToMap([]int64{1, 2}, "g", 0), AggregatingAttributesClear: lib.ConvertDataToMap([]int64{0, 1, 4, 3, 0}, "s", 0)}
	testData[2] = lib.DpClearResponse{WhereClear: lib.ConvertDataToMap([]int64{1, 3}, "w", 0), GroupByClear: lib.ConvertDataToMap([]int64{1, 3}, "g", 0), AggregatingAttributesClear: lib.ConvertDataToMap([]int64{0, 1, 0, 1, 0}, "s", 0)}

	testData[3] = lib.DpClearResponse{WhereClear: lib.ConvertDataToMap([]int64{1, 1}, "w", 0), GroupByClear: lib.ConvertDataToMap([]int64{1, 1}, "g", 0), AggregatingAttributesClear: lib.ConvertDataToMap([]int64{0, 0, 0, 0, 0}, "w", 0)}
	testData[4] = lib.DpClearResponse{WhereClear: lib.ConvertDataToMap([]int64{1, 2}, "w", 0), GroupByClear: lib.ConvertDataToMap([]int64{1, 2}, "g", 0), AggregatingAttributesClear: lib.ConvertDataToMap([]int64{1, 3, 5, 7, 1}, "w", 0)}
	testData[5] = lib.DpClearResponse{WhereClear: lib.ConvertDataToMap([]int64{1, 3}, "w", 0), GroupByClear: lib.ConvertDataToMap([]int64{1, 3}, "g", 0), AggregatingAttributesClear: lib.ConvertDataToMap([]int64{1, 0, 1, 0, 1}, "w", 0)}

	return testData
}
