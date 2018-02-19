package protocolsUnLynx_test

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
	protocol := rootInstance.(*protocolsUnLynx.LocalClearAggregationProtocol)

	testData := generateClearData()
	aggregatedData := libUnLynx.AddInClear(testData)

	protocol.TargetOfAggregation = testData
	feedback := protocol.FeedbackChannel

	go protocol.Start()

	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond

	select {
	case results := <-feedback:
		assert.Equal(t, dataUnLynx.CompareClearResponses(results, aggregatedData), true)
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}
}

func generateClearData() []libUnLynx.DpClearResponse {
	testData := make([]libUnLynx.DpClearResponse, 6)

	testData[0] = libUnLynx.DpClearResponse{WhereClear: libUnLynx.ConvertDataToMap([]int64{1, 1}, "w", 0), GroupByClear: libUnLynx.ConvertDataToMap([]int64{1, 1}, "g", 0), AggregatingAttributesClear: libUnLynx.ConvertDataToMap([]int64{1, 2, 3, 4, 5}, "s", 0)}
	testData[1] = libUnLynx.DpClearResponse{WhereClear: libUnLynx.ConvertDataToMap([]int64{1, 2}, "w", 0), GroupByClear: libUnLynx.ConvertDataToMap([]int64{1, 2}, "g", 0), AggregatingAttributesClear: libUnLynx.ConvertDataToMap([]int64{0, 1, 4, 3, 0}, "s", 0)}
	testData[2] = libUnLynx.DpClearResponse{WhereClear: libUnLynx.ConvertDataToMap([]int64{1, 3}, "w", 0), GroupByClear: libUnLynx.ConvertDataToMap([]int64{1, 3}, "g", 0), AggregatingAttributesClear: libUnLynx.ConvertDataToMap([]int64{0, 1, 0, 1, 0}, "s", 0)}

	testData[3] = libUnLynx.DpClearResponse{WhereClear: libUnLynx.ConvertDataToMap([]int64{1, 1}, "w", 0), GroupByClear: libUnLynx.ConvertDataToMap([]int64{1, 1}, "g", 0), AggregatingAttributesClear: libUnLynx.ConvertDataToMap([]int64{0, 0, 0, 0, 0}, "w", 0)}
	testData[4] = libUnLynx.DpClearResponse{WhereClear: libUnLynx.ConvertDataToMap([]int64{1, 2}, "w", 0), GroupByClear: libUnLynx.ConvertDataToMap([]int64{1, 2}, "g", 0), AggregatingAttributesClear: libUnLynx.ConvertDataToMap([]int64{1, 3, 5, 7, 1}, "w", 0)}
	testData[5] = libUnLynx.DpClearResponse{WhereClear: libUnLynx.ConvertDataToMap([]int64{1, 3}, "w", 0), GroupByClear: libUnLynx.ConvertDataToMap([]int64{1, 3}, "g", 0), AggregatingAttributesClear: libUnLynx.ConvertDataToMap([]int64{1, 0, 1, 0, 1}, "w", 0)}

	return testData
}
