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
	//utils.PrintTime("ShareData")
	testingData :=[]*big.Int{big.NewInt(1)}

	inputs := make([]*big.Int,0)
	for f := 0; f < len(testingData); f++ {
		inputs = append(inputs, toArrayBit(testingData[f])...)
	}

	// Evaluate the Valid() circuit
	ckt := ConfigToCircuit(testingData)

	//can only evaluate on bit values,
	ckt.Eval(inputs)
	log.Lvl1("inputs are ",testingData)
	log.Lvl1("output 1 is", ckt.Outputs()[0].WireValue)
	//log.Lvl1("output 2 is ", ckt.Outputs()[1].WireValue)
	//we have more than 1 output, we have numberServ output, each are the share that the server will get
	log.Lvl1("there are ", len(ckt.Outputs()) , " outputs")

	log.Lvl1("there are", len(ckt.MulGates()), " mul gates")


	// Generate sharings of the input wires and the multiplication gate wires
	log.Lvl1("before sharing wires ", prg)
	ckt.ShareWires(prg)
	log.Lvl1(" After Sharing wire ", prg)
	// log.Lvl1(len(Prg.Hints(0).Delta))
	//test := (big.NewInt(0).Add(Prg.Hints(0).Delta[1],Prg.Hints(0).Delta[0]))
	//log.Lvl1(test.Mod(test,ckt.Modulus()));

	// Construct polynomials f, g, and h and share evaluations of h
	sharePolynomials(ckt, prg)
	log.Lvl1("After sharing polynomials", prg)

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

func ConfigToCircuit(datas []*big.Int) *circuit.Circuit {

	nf := len(datas)
	ckts := make([]*circuit.Circuit, nf)
	for f := 0; f < nf; f++ {
		name := "circuit"
		name+= datas[f].String()
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