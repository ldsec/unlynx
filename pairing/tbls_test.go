package bls

import (
	"testing"

	"github.com/dedis/paper_17_dfinity/pedersen/dkg"
	"github.com/dedis/paper_17_dfinity/pedersen/vss"
	"github.com/stretchr/testify/require"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1/network"
)

var pairing = network.Pairing

var suite = network.Suite

var nbParticipants = 7

var partPubs []abstract.Point
var partSec []abstract.Scalar

var dkgs []*dkg.DistKeyGenerator

func init() {
	partPubs = make([]abstract.Point, nbParticipants)
	partSec = make([]abstract.Scalar, nbParticipants)
	for i := 0; i < nbParticipants; i++ {
		sec, pub := genPair()
		partPubs[i] = pub
		partSec[i] = sec
		//generated := suite.Point().Mul(nil, partSec[i])
		//fmt.Printf("Key[%d] priv: %s, pub %s , generated %s\n", i, sec.String(), pub.String(), generated.String())
	}
	dkgs = dkgGen()
}

func TestThresholdBLS(t *testing.T) {
	fullExchange(t)
	dkg := dkgs[0]
	dks, err := dkg.DistKeyShare()
	require.Nil(t, err)

	xiG := suite.Point().Mul(nil, dks.PriShare().V)
	xiG2 := dks.Polynomial().Eval(dks.PriShare().I).V
	require.Equal(t, xiG.String(), xiG2.String())

	msg := []byte("Hello World")
	tsig := ThresholdSign(pairing, dks, msg)
	require.Nil(t, err)

	require.True(t, ThresholdVerify(pairing, dks.Polynomial(), msg, tsig))

	sigs := make([]*ThresholdSig, nbParticipants)
	for i, d := range dkgs {
		dks, err := d.DistKeyShare()
		require.Nil(t, err)
		sigs[i] = ThresholdSign(pairing, dks, msg)
	}
	tt := nbParticipants/2 + 1
	sig, err := AggregateSignatures(pairing, dks.Polynomial(), msg, sigs, nbParticipants, tt)
	require.Nil(t, err)
	require.Nil(t, Verify(pairing, dks.Polynomial().Commit(), msg, sig))
}

func dkgGen() []*dkg.DistKeyGenerator {
	dkgs := make([]*dkg.DistKeyGenerator, nbParticipants)
	for i := 0; i < nbParticipants; i++ {
		dkg, err := dkg.NewDistKeyGenerator(suite, partSec[i], partPubs, random.Stream, nbParticipants/2+1)
		if err != nil {
			panic(err)
		}
		dkgs[i] = dkg
	}
	return dkgs
}

func fullExchange(t *testing.T) {
	dkgs = dkgGen()
	// full secret sharing exchange
	// 1. broadcast deals
	resps := make([]*dkg.Response, 0, nbParticipants*nbParticipants)
	for _, dkg := range dkgs {
		deals, err := dkg.Deals()
		require.Nil(t, err)
		for i, d := range deals {
			resp, err := dkgs[i].ProcessDeal(d)
			require.Nil(t, err)
			require.Equal(t, vss.StatusApproval, resp.Response.Status)
			resps = append(resps, resp)
		}
	}
	// 2. Broadcast responses
	for _, resp := range resps {
		for i, dkg := range dkgs {
			// ignore all messages from ourself
			if resp.Response.Index == uint32(i) {
				continue
			}
			j, err := dkg.ProcessResponse(resp)
			require.Nil(t, err)
			require.Nil(t, j)
		}
	}

}
func genPair() (abstract.Scalar, abstract.Point) {
	sc := suite.Scalar().Pick(random.Stream)
	return sc, suite.Point().Mul(nil, sc)
}
