package protocolsunlynx_test

import (
	"github.com/ldsec/unlynx/lib"
	"github.com/ldsec/unlynx/lib/aggregation"
	"github.com/ldsec/unlynx/protocols"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
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

var roster *onet.Roster

//TestCollectiveAggregationGroup tests collective aggregation protocol
func TestCollectiveAggregationGroup(t *testing.T) {
	local := onet.NewLocalTest(libunlynx.SuiTe)

	// You must register this protocol before creating the servers
	_, err := onet.GlobalProtocolRegister("CollectiveAggregationTestGroup", NewCollectiveAggregationTestGroups)
	assert.NoError(t, err, "Error registering <CollectiveAggregationTestGroup>")

	_, _, tree := local.GenTree(10, true)
	defer local.CloseAll()

	p, err := local.CreateProtocol("CollectiveAggregationTestGroup", tree)
	assert.NoError(t, err)

	protocol := p.(*protocolsunlynx.CollectiveAggregationProtocol)

	//run protocol
	go func() {
		err := protocol.Start()
		assert.NoError(t, err)
	}()
	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*10) * time.Millisecond

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
		testCVMap[groupingAttrA.Key()] = libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 1}), AggregatingAttributes: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 2, 3, 4, 5})}
		testCVMap[groupingAttrB.Key()] = libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 2}), AggregatingAttributes: *libunlynx.EncryptIntVector(clientPublic, []int64{0, 0, 0, 0, 0})}
	case 1:
		testCVMap[groupingAttrB.Key()] = libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 2}), AggregatingAttributes: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 2, 3, 4, 5})}
	case 2:
		testCVMap[groupingAttrA.Key()] = libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 1}), AggregatingAttributes: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 1, 1, 1, 1})}
	case 9:
		testCVMap[groupingAttrC.Key()] = libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(clientPublic, []int64{3, 3}), AggregatingAttributes: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 0, 1, 0, 1})}
		testCVMap[groupingAttrA.Key()] = libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 1}), AggregatingAttributes: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 2, 3, 4, 5})}
	case 5:
		testCVMap[groupingAttrC.Key()] = libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(clientPublic, []int64{3, 3}), AggregatingAttributes: *libunlynx.EncryptIntVector(clientPublic, []int64{0, 1, 0, 1, 0})}

	default:
	}
	protocol.GroupedData = &testCVMap

	return protocol, err
}

func TestCollectiveAggregationSimple(t *testing.T) {
	local := onet.NewLocalTest(libunlynx.SuiTe)

	// You must register this protocol before creating the servers
	_, err := onet.GlobalProtocolRegister("CollectiveAggregationTestSimple", NewCollectiveAggregationTestSimple)
	assert.NoError(t, err, "Error registering <CollectiveAggregationTestSimple>:")

	_, _, tree := local.GenTree(10, true)
	defer local.CloseAll()

	p, err := local.CreateProtocol("CollectiveAggregationTestSimple", tree)
	assert.NoError(t, err)

	protocol := p.(*protocolsunlynx.CollectiveAggregationProtocol)

	//run protocol
	go func() {
		err := protocol.Start()
		assert.NoError(t, err)
	}()
	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*10) * time.Millisecond

	feedback := protocol.FeedbackChannel

	//verify results
	expectedResults := []int64{4, 6, 8, 10, 12}

	select {
	case encryptedResult := <-feedback:
		log.Lvl1("Received results:")
		resultData := make([]int64, len(encryptedResult.GroupedData[protocolsunlynx.EMPTYKEY].AggregatingAttributes))
		aggrAttr := encryptedResult.GroupedData[protocolsunlynx.EMPTYKEY].AggregatingAttributes
		resultData = libunlynx.DecryptIntVector(clientPrivate, &aggrAttr)
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
		toAdd := libunlynx.EncryptIntVector(clientPublic, []int64{1, 2, 3, 4, 5})
		simpleSlice = append(simpleSlice, *toAdd...)
	case 1:
		toAdd := libunlynx.EncryptIntVector(clientPublic, []int64{1, 2, 3, 4, 5})
		simpleSlice = append(simpleSlice, *toAdd...)
	case 2:
		toAdd := libunlynx.EncryptIntVector(clientPublic, []int64{1, 1, 1, 1, 1})
		simpleSlice = append(simpleSlice, *toAdd...)
	case 5:
		toAdd := libunlynx.EncryptIntVector(clientPublic, []int64{0, 1, 0, 1, 0})
		simpleSlice = append(simpleSlice, *toAdd...)
	case 9:
		toAdd := libunlynx.EncryptIntVector(clientPublic, []int64{1, 0, 1, 0, 1})
		simpleSlice = append(simpleSlice, *toAdd...)
	default:
	}

	protocol.SimpleData = &simpleSlice
	protocol.GroupedData = nil
	protocol.Proofs = true
	protocol.ProofFunc = func(data []libunlynx.CipherVector, res libunlynx.CipherVector) *libunlynxaggr.PublishedAggregationListProof {
		proof := libunlynxaggr.AggregationListProofCreation(data, res)
		return &proof
	}

	return protocol, err
}

func TestCollectiveAggregationDiffSizes(t *testing.T) {
	local := onet.NewLocalTest(libunlynx.SuiTe)

	// You must register this protocol before creating the servers
	_, err := onet.GlobalProtocolRegister("CollectiveAggregationDiffSizes", NewCollectiveAggregationDiffSizes)
	assert.NoError(t, err, "Error registering <CollectiveAggregationDiffSizes>:")

	_, rosterNew, tree := local.GenTree(10, true)
	defer local.CloseAll()
	roster = rosterNew

	p, err := local.CreateProtocol("CollectiveAggregationDiffSizes", tree)
	assert.NoError(t, err)

	protocol := p.(*protocolsunlynx.CollectiveAggregationProtocol)

	//run protocol
	go func() {
		err := protocol.Start()
		assert.NoError(t, err)
	}()
	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*10) * time.Millisecond

	feedback := protocol.FeedbackChannel

	//verify results
	expectedResults := []int64{4, 6, 8, 10, 12, 9, 9, 6}

	select {
	case encryptedResult := <-feedback:
		log.Lvl1("Received results:")
		resultData := make([]int64, len(encryptedResult.GroupedData[protocolsunlynx.EMPTYKEY].AggregatingAttributes))
		aggrAttr := encryptedResult.GroupedData[protocolsunlynx.EMPTYKEY].AggregatingAttributes

		// get full decryption key
		aggrSk := roster.List[0].GetPrivate()
		for i := 1; i < len(roster.List); i++ {
			aggrSk.Add(aggrSk, roster.List[i].GetPrivate())
		}
		resultData = libunlynx.DecryptIntVector(aggrSk, &aggrAttr)
		assert.Equal(t, expectedResults, resultData)
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}
}

func NewCollectiveAggregationDiffSizes(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pi, err := protocolsunlynx.NewCollectiveAggregationProtocol(tni)
	protocol := pi.(*protocolsunlynx.CollectiveAggregationProtocol)

	simpleSlice := make([]libunlynx.CipherText, 0)
	switch tni.Index() {
	case 0:
		toAdd := libunlynx.EncryptIntVector(roster.Aggregate, []int64{1, 1, 1, 1, 1, 2})
		simpleSlice = append(simpleSlice, *toAdd...)
	case 1:
		toAdd := libunlynx.EncryptIntVector(roster.Aggregate, []int64{1, 2, 3, 4, 5, 3, 4})
		simpleSlice = append(simpleSlice, *toAdd...)
	case 2:
		toAdd := libunlynx.EncryptIntVector(roster.Aggregate, []int64{1, 2, 3, 4, 5, 3, 5, 6})
		simpleSlice = append(simpleSlice, *toAdd...)
	case 5:
		toAdd := libunlynx.EncryptIntVector(roster.Aggregate, []int64{0, 1, 0, 1, 0, 0, 0, 0})
		simpleSlice = append(simpleSlice, *toAdd...)
	case 9:
		toAdd := libunlynx.EncryptIntVector(roster.Aggregate, []int64{1, 0, 1, 0, 1, 1})
		simpleSlice = append(simpleSlice, *toAdd...)
	default:
	}

	protocol.Pubkey = clientPublic
	protocol.SimpleData = &simpleSlice
	protocol.GroupedData = nil
	protocol.Proofs = false

	return protocol, err
}
