package pairing

import (
	"testing"
	"gopkg.in/dedis/crypto.v0/random"
	"math"
	"gopkg.in/dedis/crypto.v0/abstract"
	"github.com/dedis/paper_17_dfinity/pbc"

	"github.com/lca1/unlynx/lib"

//	"gopkg.in/dedis/onet.v1/network"
	"github.com/dedis/kyber/xof/blake"
	"gopkg.in/dedis/onet.v1/log"
	"github.com/stretchr/testify/assert"
	//"gopkg.in/dedis/onet.v1/network"
	"gopkg.in/dedis/onet.v1/network"
)

//THIS IS AN HARDCODED TEST. The goal was to experiment how was working the pairing over the elliptic curve
//and verify the math and formula computations.
//The real protocol will be in the package lib/proofs

// Range will be [0,2^l)
var suite = network.Suite
var pairing = pbc.NewPairingFp254BNb()
//var suite = pairing.G2()


var p, P = genPair()
var r = suite.Scalar().Pick(random.Stream)
//info from verifier
var u = 2.0
var l = 6.0
var ul = math.Pow(u,l)
var B = suite.Point().Base()
var x, y = lib.GenKey()
var A = make([]abstract.Point,int(u))
var i = int64(0)
var v = make([]abstract.Scalar,int(l))
var V = make([]abstract.Point,int(l))
//info from prover
var phiT = suite.Scalar().SetInt64(int64(30))
var phiF = suite.Scalar().SetInt64(int64(65))
var bitT = []int{0,1,1,1,1,0}//30 phi_j
var bitF = []int{1,1,1,1,1,1}//63 phi_j
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
var sj,tj,mj = make([]abstract.Scalar,0),make([]abstract.Scalar,0),make([]abstract.Scalar,0)


func genPair() (abstract.Scalar, abstract.Point) {
	sc := suite.Scalar().Pick(blake.New(nil))
	return sc, suite.Point().Mul(nil, sc)
}



func init() {
	log.LLvl1("Range is [0,",ul,")")
	for i=0; i < int64(u) ; i++ {
		scalar := pairing.G1().Scalar().SetInt64(i)
		invert := pairing.G1().Scalar().Add(x,scalar)
		A[i] = pairing.G1().Point().Mul(pairing.G1().Point().Base(),pairing.G1().Scalar().Inv(invert))
	}
	for j:=0;j<len(bitT) ; j++ {

		v[j] = pairing.G1().Scalar().Pick(random.Stream)
		///V_j = B(x+phi_j)^-1(v_j)
		V[j] = pairing.G1().Point().Mul(A[bitT[j]],v[j])
		//PK
		sj= append(sj,suite.Scalar().Pick(random.Stream))
		tj = append(tj,suite.Scalar().Pick(random.Stream))
		mj = append(mj,suite.Scalar().Pick(random.Stream))
		m.Add(m,mj[j])
		//Compute D
		//Bu^js_j
		firstT := suite.Point().Mul(B,suite.Scalar().Mul(sj[j],suite.Scalar().SetInt64(int64(math.Pow(u,float64(j))))))
		D.Add(D,firstT)
		secondT := suite.Point().Mul(P,mj[j])
		D.Add(D,secondT)
		//Compute a_j
		a[j] = pairing.GT().PointGT().Pairing(V[j],suite.Point().Mul(suite.Point().Base(),suite.Scalar().Neg(sj[j])))
		a[j].Add(a[j],pairing.GT().PointGT().Pairing(pairing.G1().Point().Base(),suite.Point().Mul(B,tj[j])))
		}



}

func TestRangeProof(t *testing.T) {

	Zr = suite.Scalar().Sub(m,suite.Scalar().Mul(r,c))
	//a'_j = e(V_j,y)*c + e(V_j,B)*(-Zphi_j) +e(B,B)*(Zv_j)
	ap := make([]abstract.Point,len(Zphi))
	//Dp = Cc + PZr
	Dp := suite.Point().Add(suite.Point().Mul(CommitT,c),suite.Point().Mul(P,Zr))
	for j:=0;j<len(Zphi);j++  {
		//compute cst
		Zphi[j] = suite.Scalar().Sub(sj[j],suite.Scalar().Mul(suite.Scalar().SetInt64(int64(bitT[j])),c))
		ZV[j] = suite.Scalar().Sub(tj[j],suite.Scalar().Mul(v[j],c))

		//p = Bu^jZphi_j
		point := suite.Point().Mul(B,suite.Scalar().SetInt64(int64(math.Pow(u,(float64(j))))))
		point.Mul(point,Zphi[j])
		Dp.Add(Dp,point)

		//check bipairing

		ap[j] = pairing.GT().PointGT().Pairing(V[j],suite.Point().Mul(y,c))
		ap[j].Add(ap[j],pairing.GT().PointGT().Pairing(V[j],suite.Point().Mul(B,suite.Scalar().Neg(Zphi[j]))))
		ap[j].Add(ap[j],pairing.GT().PointGT().Pairing(pairing.G1().Point().Base(),suite.Point().Mul(B,ZV[j])))
		assert.Equal(t,ap[j],a[j])
		}

	result := Dp.Equal(D)
	assert.True(t,result)

}
