package prio_utils

import (
	"math/big"
	"github.com/henrycg/prio/share"
	"github.com/henrycg/prio/circuit"
	"github.com/henrycg/prio/utils"
	"github.com/henrycg/prio/poly"

)

// Checker holds all of the state needed to check the validity
// of a single client submission.
type Checker struct {
	req *Request
	Prg *share.ReplayPRG

	mod *big.Int
	ckt *circuit.Circuit

	n int // Number of fixed points on f and g (mulGates + 1)
	N int // n rounded up to a power of two

	pointsF []*big.Int
	pointsG []*big.Int
	pointsH []*big.Int

	evalF *big.Int
	evalG *big.Int
	evalH *big.Int
}



func NewChecker(ckt *circuit.Circuit, serverIdx int, leaderIdx int) *Checker {
	c := new(Checker)
	c.Prg = share.NewReplayPRG(serverIdx, leaderIdx)
	c.ckt = ckt
	c.mod = c.ckt.Modulus()

	c.n = len(c.ckt.MulGates()) + 1
	c.N = utils.NextPowerOfTwo(c.n)

	c.pointsF = make([]*big.Int, c.N)
	c.pointsG = make([]*big.Int, c.N)
	c.pointsH = make([]*big.Int, 2*c.N-1)

	c.evalF = new(big.Int)
	c.evalG = new(big.Int)
	c.evalH = new(big.Int)

	return c
}

func (c *Checker) SetReq(req *Request) {
	c.req = req
	c.Prg.Import(req.Hint)

	// Reconstruct shares of internal wires using
	// client-provided values.
	c.ckt.ImportWires(c.Prg)

}

type CheckerPrecomp struct {
	x *big.Int

	degN  *poly.BatchPre
	deg2N *poly.BatchPre

	xN  *poly.PreX
	x2N *poly.PreX
}


func (pre *CheckerPrecomp) SetCheckerPrecomp(x *big.Int) {
	pre.x = x
	pre.xN = pre.degN.NewEvalPoint(x)
	pre.x2N = pre.deg2N.NewEvalPoint(x)
}


func NewCheckerPrecomp(ckt *circuit.Circuit) *CheckerPrecomp {
	pre := new(CheckerPrecomp)

	// This is the number of fixed points on f and g. It's
	// the number of multiplication gates plus one for the
	// constant term.
	n := len(ckt.MulGates()) + 1
	N := utils.NextPowerOfTwo(n)

	rootsN := share.GetRoots(N)
	roots2N := share.GetRoots(2 * N)

	pre.degN = poly.NewBatch(ckt.Modulus(), rootsN)
	pre.deg2N = poly.NewBatch(ckt.Modulus(), roots2N[0:2*N-1])

	return pre
}

type CheckerPool struct {
	ckt			*circuit.Circuit
	serverIdx int
	leaderIdx int
	buffer    chan *Checker
}

func (p *CheckerPool) Get() *Checker {
	select {
	case out := <-p.buffer:
		return out
		//	default:
		//		return mpc.NewChecker(p.cfg, p.serverIdx, p.leaderIdx)
	}
}

func NewCheckerPool(ckt *circuit.Circuit, serverIdx int, leaderIdx int) *CheckerPool {
	out := new(CheckerPool)
	out.ckt = ckt
	out.serverIdx = serverIdx
	out.leaderIdx = leaderIdx

	out.buffer = make(chan *Checker, 5)
	for i := 0; i < 5; i++ {
		out.buffer <- NewChecker(ckt, serverIdx, leaderIdx)
	}
	return out
}

type CorShare struct {
	ShareD *big.Int
	ShareE *big.Int
}

func (c *Checker) evalPoly(pre *CheckerPrecomp) {
	mulGates := c.ckt.MulGates()
	// Recover constant terms of the polynomials f, g, and h.
	c.pointsF[0] = c.Prg.Get(c.mod)
	c.pointsG[0] = c.Prg.Get(c.mod)
	c.pointsH[0] = c.Prg.Get(c.mod)

	// For all multiplication triples a_i * b_i = c_i,
	//    polynomial [f(x)] has [f(i)] = [a_i]
	//    polynomial [g(x)] has [g(i)] = [b_i]
	for i := 1; i < c.n; i++ {
		c.pointsF[i] = mulGates[i-1].ParentL.WireValue
		c.pointsG[i] = mulGates[i-1].ParentR.WireValue
		c.pointsH[2*i] = mulGates[i-1].WireValue
	}

	// Pad the high-order coefficients with zeros
	for i := c.n; i < c.N; i++ {
		c.pointsF[i] = utils.Zero
		c.pointsG[i] = utils.Zero
		c.pointsH[2*i] = utils.Zero
	}

	for i := 1; i < 2*c.N-1; i += 2 {
		c.pointsH[i] = c.Prg.Get(c.mod)
	}

	c.evalF.Set(pre.xN.Eval(c.pointsF))
	c.evalG.Set(pre.xN.Eval(c.pointsG))
	c.evalG.Mul(c.evalG, pre.x)
	c.evalG.Mod(c.evalG, c.mod)

	c.evalH.Set(pre.x2N.Eval(c.pointsH))
	c.evalH.Mul(c.evalH, pre.x)
	c.evalH.Mod(c.evalH, c.mod)
}

func (c *Checker) CorShare (pre *CheckerPrecomp) (*CorShare) {
	c.evalPoly(pre)

	out := new(CorShare)

	out.ShareD = new(big.Int)
	out.ShareE = new(big.Int)

	// Let the multiplication triple be: (a, b, c)
	// where a*b = c. We want to compute z = x*y.

	// [d]_i = [x]_i - [a]_i
	out.ShareD.Sub(c.evalF, c.req.TripleShare.ShareA)
	out.ShareD.Mod(out.ShareD, c.mod)

	// [e]_i = [y]_i - [b]_i
	out.ShareE.Sub(c.evalG, c.req.TripleShare.ShareB)
	out.ShareE.Mod(out.ShareE, c.mod)

	return out
}

type OutShare struct {
	Check *big.Int
}

type Cor struct {
	D *big.Int
	E *big.Int
}

func (c *Checker) OutShare( corIn *Cor, key *utils.PRGKey)(sol *OutShare) {
	// We have shares of a bunch of values (v1, v2, ..., vK) that should
	// all be zero. To check them, the servers sample random values
	// (r1, r2, ..., rK) and compute the inner product:
	//   CHECK = \sum_i (r_i * v_i).
	// If any v_i is non-zero, then the CHECK value will be non-zero whp.
	out := new(OutShare)
	mulCheck := new(big.Int)
	// [z]_i = d*e + d*[b]_i + e*[a]_i + [c]_i
	if c.Prg.IsLeader() {
		mulCheck.Mul(corIn.D, corIn.E)
	}

	term := new(big.Int)
	term.Mul(corIn.D, c.req.TripleShare.ShareB)
	mulCheck.Add(mulCheck, term)

	term.Mul(corIn.E, c.req.TripleShare.ShareA)
	mulCheck.Add(mulCheck, term)

	mulCheck.Add(mulCheck, c.req.TripleShare.ShareC)
	mulCheck.Mod(mulCheck, c.mod)

	// We want to check if:
	//    f(r)*g(r) - h(r)  =?  0
	// so subtract off our share of h(r).
	mulCheck.Sub(mulCheck, c.evalH)
	mulCheck.Mod(mulCheck, c.mod)

	shouldBeZero := make([]*big.Int, len(c.ckt.ShouldBeZero())+1)
	shouldBeZero[0] = mulCheck
	for i, gate := range c.ckt.ShouldBeZero() {
		shouldBeZero[i+1] = gate.WireValue
	}

	out.Check = c.randSum(key, shouldBeZero)

	return out
}

func (c *Checker) randSum(key *utils.PRGKey, nums []*big.Int) *big.Int {
	rnd := utils.NewBufPRG(utils.NewPRG(key))
	tmp := new(big.Int)
	out := new(big.Int)

	for _, num := range nums {
		tmp.Mul(num, rnd.RandInt(c.mod))
		tmp.Mod(tmp, c.mod)

		out.Add(out, tmp)
	}

	out.Mod(out, c.mod)
	return out
}

func (c *Checker) Cor(sharesIn []*CorShare) *Cor {

	cor := new(Cor)
	cor.D = new(big.Int)
	cor.E = new(big.Int)

	for i := 0; i < len(sharesIn); i++ {

		cor.D.Add(cor.D, sharesIn[i].ShareD)
		cor.E.Add(cor.E, sharesIn[i].ShareE)
	}

	cor.D.Mod(cor.D, c.mod)
	cor.E.Mod(cor.E, c.mod)

	return cor
}


func (c *Checker) OutputIsValid(sharesIn []*OutShare) bool {

	check := new(big.Int)

	for _, share := range sharesIn {
		check.Add(check, share.Check)
	}
	check.Mod(check, c.mod)
	//log.Printf("BIG Wanted 0 got %v", check)

	return (check.Sign() == 0)
}
