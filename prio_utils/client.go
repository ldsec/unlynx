package prio_utils

import (
	"math/big"
	"github.com/henrycg/prio/circuit"
	"github.com/henrycg/prio/poly"
	"github.com/henrycg/prio/utils"
	"gopkg.in/dedis/onet.v1/log"
	"github.com/henrycg/prio/share"
	"github.com/henrycg/prio/triple"

)

//this should be run at client for proof start
//a ClientRequest is sent to each server from one client, for all client

type Request struct {
	Hint *share.PRGHints
	TripleShare *triple.Share
}

//Create proof submission for one client
func ClientRequest(dataShared []*big.Int, leaderForReq int) ([]*Request){
	//utils.PrintTime("Initialize")
	ns := len(dataShared)
	prg := share.NewGenPRG(ns, leaderForReq)


	out := make([]*Request, ns)
	for s := 0; s < ns; s++ {
		out[s] = new(Request)
	}

	//log.Lvl1("Inputs are")
	inputs := make([]*big.Int,0)
		for f := 0; f < len(dataShared); f++ {
		//log.Lvl1(dataShared[f])
		inputs = append(inputs, toArrayBit(dataShared[f])...)
	}

	// Evaluate the Valid() circuit
	ckt := ConfigToCircuit(dataShared)
	//log.Lvl1("When evaluate request mod is ", ckt.Modulus())
	//can only evaluate on bit values,
	ckt.Eval(inputs)
	/*log.Lvl1("Output of circuits are ")
	for i:=0;i<len(ckt.Outputs()) ;i++  {
		log.Lvl1(ckt.Outputs()[i].WireValue)
	}*/
	// Generate sharings of the input wires and the multiplication gate wires
	ckt.ShareWires(prg)



	// Construct polynomials f, g, and h and share evaluations of h
	sharePolynomials(ckt, prg)

	//generate share of beaver Triple
	triples := triple.NewTriple(share.IntModulus, ns)
	for s := 0; s < ns; s++ {
		out[s].Hint = prg.Hints(s)
		out[s].TripleShare = triples[s]
	}

	return out
}


func toArrayBit(int *big.Int) []*big.Int {
	out := make([]*big.Int,int.BitLen())
	for i := 0; i<int.BitLen(); i++  {
		out[i] = big.NewInt(int64(int.Bit(i)))
	}
	return out
}
func ConfigToCircuitBit(datas []int) *circuit.Circuit {
	nf := len(datas)
	ckts := make([]*circuit.Circuit, nf)
	for f := 0; f < nf; f++ {
		name := "circuit"
		name+= string(f)
		ckts[f] = int_Circuit(name, datas[f])
	}

	ckt := circuit.AndCircuits(ckts)
	return ckt
}

func ConfigToCircuit(datas []*big.Int) *circuit.Circuit {

	nf := len(datas)
	ckts := make([]*circuit.Circuit, nf)
	for f := 0; f < nf; f++ {
		name := "circuit"
		name+= string(f)
		ckts[f] = int_Circuit(name, int(datas[f].BitLen()))
	}

	ckt := circuit.AndCircuits(ckts)
	return ckt
}



func sharePolynomials(ckt *circuit.Circuit, prg *share.GenPRG){
	mulGates := ckt.MulGates()
	mod := ckt.Modulus()

	// Little n the number of points on the polynomials.
	// The constant term is randomized, so it's (mulGates + 1).
	n := len(mulGates) + 1
	log.Lvl1("Mulgates: ", n)

	// Big N is n rounded up to a power of two
	N := utils.NextPowerOfTwo(n)

	// Get the n2-th roots of unity
	pointsF := make([]*big.Int, N)
	pointsG := make([]*big.Int, N)
	zeros := make([]*big.Int, N)
	for i := 0; i < N; i++ {
		zeros[i] = utils.Zero
	}


	// Compute f(x) and g(x)
	pointsF[0] = prg.ShareRand(mod)
	pointsG[0] = prg.ShareRand(mod)

	// Send a sharing of h(0) = f(0)*g(0).
	h0 := new(big.Int)
	h0.Mul(pointsF[0], pointsG[0])
	h0.Mod(h0, mod)
	prg.Share(mod, h0)

	for i := 1; i < n; i++ {
		pointsF[i] = mulGates[i-1].ParentL.WireValue
		pointsG[i] = mulGates[i-1].ParentR.WireValue
	}

	// Zero pad the upper coefficients of f(x) and g(x)
	for i := n; i < N; i++ {
		pointsF[i] = utils.Zero
		pointsG[i] = utils.Zero
	}

	// Interpolate through the Nth roots of unity
	polyF := poly.InverseFFT(pointsF)
	polyG := poly.InverseFFT(pointsG)
	paddedF := append(polyF, zeros...)
	paddedG := append(polyG, zeros...)

	// Evaluate at all 2N-th roots of unity
	evalsF := poly.FFT(paddedF)
	evalsG := poly.FFT(paddedG)

	// We need to send to the servers the evaluations of
	//   f(r) * g(r)
	// for all 2N-th roots of unity r that are not also
	// N-th roots of unity.
	hint := new(big.Int)
	for i := 1; i < 2*N-1; i += 2 {
		hint.Mul(evalsF[i], evalsG[i])
		hint.Mod(hint, mod)
		prg.Share(mod, hint)
	}
}