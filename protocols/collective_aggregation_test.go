package protocolsunlynx_test

import (
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/protocols"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
	"time"
)

var clientPrivate = libunlynx.SuiTe.Scalar().Pick(random.New())
var clientPublic = libunlynx.SuiTe.Point().Mul(clientPrivate, libunlynx.SuiTe.Point().Base())
var grpattr1 = libunlynx.DeterministCipherText{Point: libunlynx.SuiTe.Point().Base()}
var grpattr2 = libunlynx.DeterministCipherText{Point: libunlynx.SuiTe.Point().Null()}
var groupingAttrA = libunlynx.DeterministCipherVector{grpattr1, grpattr1}
var groupingAttrB = libunlynx.DeterministCipherVector{grpattr2, grpattr2}
var groupingAttrC = libunlynx.DeterministCipherVector{grpattr1, grpattr2}

//TestCollectiveAggregationGroup tests collective aggregation protocol
func TestCollectiveAggregationGroup(t *testing.T) {
	local := onet.NewLocalTest(libunlynx.SuiTe)

	// You must register this protocol before creating the servers
	onet.GlobalProtocolRegister("CollectiveAggregationTestGroup", NewCollectiveAggregationTestGroups)
	_, _, tree := local.GenTree(10, true)
	defer local.CloseAll()

	p, err := local.CreateProtocol("CollectiveAggregationTestGroup", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}
	protocol := p.(*protocolsunlynx.CollectiveAggregationProtocol)

	//run protocol
	go protocol.Start()
	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond

	feedback := protocol.FeedbackChannel

	//verify results
	expectedGroups := map[libunlynx.GroupingKey][]int64{groupingAttrA.Key(): {1, 1},
		groupingAttrB.Key(): {1, 2},
		groupingAttrC.Key(): {3, 3}}

	expectedResults := map[libunlynx.GroupingKey][]int64{groupingAttrA.Key(): {3, 5, 7, 9, 11},
		groupingAttrB.Key(): {1, 2, 3, 4, 5},
		groupingAttrC.Key(): {1, 1, 1, 1, 1}}

	select {
	case encryptedResult := <-feedback:
		log.Lvl1("Received results:")
		resultData := make(map[libunlynx.GroupingKey][]int64)
		for k, v := range encryptedResult.GroupedData {
			resultData[k] = libunlynx.DecryptIntVector(clientPrivate, &v.AggregatingAttributes)

			log.Lvl1(k, resultData[k])
		}
		for k, v1 := range expectedGroups {
			if v2, ok := encryptedResult.GroupedData[k]; ok {
				assert.True(t, ok)
				_ = v1
				_ = v2
				assert.True(t, reflect.DeepEqual(v1, libunlynx.DecryptIntVector(clientPrivate, &v2.GroupByEnc)))
				delete(encryptedResult.GroupedData, k)
			}
		}
		assert.Empty(t, encryptedResult.GroupedData)
		assert.Equal(t, expectedResults, resultData)
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}
}

// NewCollectiveAggregationTest is a test specific protocol instance constructor that injects test data.
func NewCollectiveAggregationTestGroups(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {

	pi, err := protocolsunlynx.NewCollectiveAggregationProtocol(tni)
	protocol := pi.(*protocolsunlynx.CollectiveAggregationProtocol)

	testCVMap := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)

	switch tni.Index() {
	case 0:
		log.Lvl1("0")
		testCVMap[groupingAttrA.Key()] = libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 1}), AggregatingAttributes: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 2, 3, 4, 5})}
		testCVMap[groupingAttrB.Key()] = libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 2}), AggregatingAttributes: *libunlynx.EncryptIntVector(clientPublic, []int64{0, 0, 0, 0, 0})}
	case 1:
		log.Lvl1("1")
		testCVMap[groupingAttrB.Key()] = libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 2}), AggregatingAttributes: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 2, 3, 4, 5})}
	case 2:
		log.Lvl1("2")
		testCVMap[groupingAttrA.Key()] = libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 1}), AggregatingAttributes: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 1, 1, 1, 1})}
	case 9:
		log.Lvl1("9")
		testCVMap[groupingAttrC.Key()] = libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(clientPublic, []int64{3, 3}), AggregatingAttributes: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 0, 1, 0, 1})}
		testCVMap[groupingAttrA.Key()] = libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 1}), AggregatingAttributes: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 2, 3, 4, 5})}
	case 5:
		log.Lvl1("5")
		testCVMap[groupingAttrC.Key()] = libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(clientPublic, []int64{3, 3}), AggregatingAttributes: *libunlynx.EncryptIntVector(clientPublic, []int64{0, 1, 0, 1, 0})}

	default:
	}
	protocol.GroupedData = &testCVMap

	return protocol, err
}

func TestCollectiveAggregationSimple(t *testing.T) {
	local := onet.NewLocalTest(libunlynx.SuiTe)

	// You must register this protocol before creating the servers
	onet.GlobalProtocolRegister("CollectiveAggregationTestSimple", NewCollectiveAggregationTestSimple)
	_, _, tree := local.GenTree(10, true)
	defer local.CloseAll()

	p, err := local.CreateProtocol("CollectiveAggregationTestSimple", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}
	protocol := p.(*protocolsunlynx.CollectiveAggregationProtocol)

	//run protocol
	go protocol.Start()
	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond

	feedback := protocol.FeedbackChannel

	//verify results
	expectedResults := []int64{4, 6, 8, 10, 12}

	select {
	case encryptedResult := <-feedback:
		log.Lvl1("Received results:")
		resultData := make([]int64, len(encryptedResult.GroupedData[protocolsunlynx.EMPTYKEY].AggregatingAttributes))
		tmp := encryptedResult.GroupedData[protocolsunlynx.EMPTYKEY].AggregatingAttributes
		resultData = libunlynx.DecryptIntVector(clientPrivate, &tmp)
		log.Lvl1(resultData)
		assert.Equal(t, expectedResults, resultData)
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}
}

func NewCollectiveAggregationTestSimple(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pi, err := protocolsunlynx.NewCollectiveAggregationProtocol(tni)
	protocol := pi.(*protocolsunlynx.CollectiveAggregationProtocol)

	simpleSlice := make([]libunlynx.CipherText, 0)
	switch tni.Index() {
	case 0:
		log.Lvl1("0")
		toAdd := libunlynx.EncryptIntVector(clientPublic, []int64{1, 2, 3, 4, 5})
		simpleSlice = append(simpleSlice, *toAdd...)
	case 1:
		log.Lvl1("1")
		toAdd := libunlynx.EncryptIntVector(clientPublic, []int64{1, 2, 3, 4, 5})
		simpleSlice = append(simpleSlice, *toAdd...)
	case 2:
		log.Lvl1("2")
		toAdd := libunlynx.EncryptIntVector(clientPublic, []int64{1, 1, 1, 1, 1})
		simpleSlice = append(simpleSlice, *toAdd...)
	case 5:
		log.Lvl1("5")
		toAdd := libunlynx.EncryptIntVector(clientPublic, []int64{0, 1, 0, 1, 0})
		simpleSlice = append(simpleSlice, *toAdd...)
	case 9:
		log.Lvl1("9")
		toAdd := libunlynx.EncryptIntVector(clientPublic, []int64{1, 0, 1, 0, 1})
		simpleSlice = append(simpleSlice, *toAdd...)
	default:
	}

	protocol.SimpleData = &simpleSlice
	protocol.GroupedData = nil

	return protocol, err
}
