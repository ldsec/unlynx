package protocolsunlynx_test

import (
	"testing"
	"time"

	"github.com/lca1/unlynx/lib/shuffle"

	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/protocols"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

func TestShufflingPlusDDTProtocol(t *testing.T) {
	defer log.AfterTest(t)

	local := onet.NewLocalTest(libunlynx.SuiTe)

	// You must register this protocol before creating the servers
	_, err := onet.GlobalProtocolRegister("ShufflingPlusDDTTest", NewShufflingPlusDDTTest)
	assert.NoError(t, err, "Failed to register the <ShufflingPlusDDTTest> protocol")

	_, _, tree := local.GenTree(nbrNodes, true)
	defer local.CloseAll()
	tree.List()

	shuffKey := tree.Roster.Aggregate.Clone()
	for i := 1; i < len(tree.List()); i++ {
		idx := tree.List()[i].RosterIndex
		privBytes, err := tree.Roster.List[idx].GetPrivate().MarshalBinary()
		assert.NoError(t, err)
		precomputes[idx] = libunlynxshuffle.CreatePrecomputedRandomize(libunlynx.SuiTe.Point().Base(), shuffKey, libunlynx.SuiTe.XOF(privBytes), 4, 10)
		shuffKey.Sub(shuffKey, tree.Roster.List[idx].Public)
	}
	idx := tree.List()[0].RosterIndex
	privBytes, err := tree.Roster.List[idx].GetPrivate().MarshalBinary()
	assert.NoError(t, err)
	precomputes[0] = libunlynxshuffle.CreatePrecomputedRandomize(libunlynx.SuiTe.Point().Base(), shuffKey, libunlynx.SuiTe.XOF(privBytes), 4, 10)

	rootInstance, err := local.CreateProtocol("ShufflingPlusDDTTest", tree)
	assert.NoError(t, err)
	protocol := rootInstance.(*protocolsunlynx.ShufflingPlusDDTProtocol)

	//create test data
	testData := make([]libunlynx.CipherVector, 4)
	for i := range testData {
		testData[i] = libunlynx.CipherVector{*libunlynx.EncryptInt(tree.Roster.Aggregate, int64(1))}
	}
	protocol.TargetData = &testData

	protocol.Proofs = true

	feedback := protocol.FeedbackChannel
	go func() {
		err := protocol.Start()
		assert.NoError(t, err)
	}()

	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*10) * time.Millisecond

	select {
	case result := <-feedback:
		for _, v := range result {
			assert.True(t, result[0][0].Equal(&v[0]))
		}
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}

}

// NewShufflingPlusDDTTest is a special purpose protocol constructor specific to tests.
func NewShufflingPlusDDTTest(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pi, err := protocolsunlynx.NewShufflingPlusDDTProtocol(tni)
	protocol := pi.(*protocolsunlynx.ShufflingPlusDDTProtocol)

	protocol.Precomputed = precomputes[tni.Index()]

	clientPrivate := libunlynx.SuiTe.Scalar().Pick(random.New())
	protocol.SurveySecretKey = &clientPrivate

	protocol.Proofs = true

	return protocol, err
}
