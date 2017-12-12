package pairing

import (
	"testing"
	"gopkg.in/dedis/crypto.v0/random"
	"math"
	"gopkg.in/dedis/crypto.v0/abstract"
	"github.com/dedis/paper_17_dfinity/pbc"
	"github.com/stretchr/testify/assert"
	"github.com/lca1/unlynx/lib"

	"gopkg.in/dedis/onet.v1/network"
)

// Range will be [0,2^l)
var suite = network.Suite
var p, P = lib.GenKey()
var r = suite.Scalar().Pick(random.Stream)
//info from verifier
var u = 2.0
var l = 5.0
var ul = math.Pow(u,l)
var B = suite.Point().Base()
var x, y = lib.GenKey()
var A = make([]abstract.Point,int(u))
var i = int64(0)
var v = make([]abstract.Scalar,int(l))
var V = make([]abstract.Point,int(l))
//info from prover
var phiT = suite.Scalar().SetInt64(int64(30))
var phiF = suite.Scalar().SetInt64(int64(35))
var bitT = []int{0,0,1,1,1,1}//30 phi_j
var bitF = []int{1,1,1,1,1,1}//32 phi_j
var CommitT = suite.Point().Add(suite.Point().Mul(B,phiT),suite.Point().Mul(P,r))
var CommitF = suite.Point().Add(suite.Point().Mul(B,phiF),suite.Point().Mul(P,r))
var vsi = make([]int64,0)
var m = suite.Scalar().SetInt64(int64(0))
var a = make([]abstract.Point,int(l))
var D = suite.Point().Null()
var Zphi = make([]abstract.Scalar,int(l))
var ZV = make([]abstract.Scalar,int(l))
var c = suite.Scalar().Pick(random.Stream)
var Zr = suite.Scalar()
var pairing = pbc.NewPairingFp254BNb()

func init() {
	for i=0; i < int64(u) ; i++ {
		scalar := suite.Scalar().SetInt64(i)
		invert := suite.Scalar().Add(x,scalar)
		A[i] = suite.Point().Mul(B,suite.Scalar().Inv(invert))
	}
	for j:=0;j<len(bitT) ; j++ {
		v[j] = suite.Scalar().Pick(random.Stream)
		///V_j = B(x+phi_j)^-1(v_j)
		V[j] = suite.Point().Mul(A[bitT[j]],v[j])
		//PK
		var sj,tj,mj = suite.Scalar().Pick(random.Stream), suite.Scalar().Pick(random.Stream), suite.Scalar().Pick(random.Stream)
		m.Add(m,mj)
		//Compute D
		//Bu^js_j
		firstT := suite.Point().Mul(B,suite.Scalar().Mul(sj,suite.Scalar().SetInt64(int64(math.Pow(u,float64(j))))))
		D.Add(D,firstT)
		secondT := suite.Point().Mul(P,mj)
		D.Add(D,secondT)
		//Compute a_j
		a[j] = suite.Point().Mul(pairing.GT().PointGT().Pairing(V[j],B),suite.Scalar().Neg(sj))
		a[j].Add(a[j],suite.Point().Mul(pairing.GT().PointGT().Pairing(B,B),tj))
		}



}

func rangeProof(t *testing.T) {
	Zr = suite.Scalar().Sub(m,suite.Scalar().Mul(r,c))
	Dp := suite.Point().Mul(CommitT,c)
	result := Dp.Equal(D)
	assert.True(t,result)
}