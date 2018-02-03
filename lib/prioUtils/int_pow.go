package prioUtils

import (
	"fmt"
	"log"
	"math/big"

	"github.com/henrycg/prio/circuit"
	"github.com/henrycg/prio/utils"
)

//File originally in Prio repository.
//Copied here to show whate can be done with each type.

func logPow(pow int) int {
	switch pow {
	case 2:
		return 1
	case 4:
		return 2
	case 8:
		return 3
	default:
		panic("Should never get here")
	}
}

func computePows(pow int, value *big.Int) []*big.Int {
	lp := logPow(pow)
	out := make([]*big.Int, lp)
	src := value
	for l := 0; l < lp; l++ {
		out[l] = new(big.Int)
		out[l].Mul(src, src)

		src = out[l]
	}

	return out
}

func intPowNewRandom(nBits int, pow int) []*big.Int {
	max := big.NewInt(1)
	max.Lsh(max, uint(nBits))
	return intPowNew(nBits, pow, utils.RandInt(max))
}

func intPowNew(nBits int, pow int, value *big.Int) []*big.Int {
	if pow != 2 && pow != 4 && pow != 8 {
		log.Fatal("pow must be in {2, 4, 8}")
	}

	intOuts := intNew(nBits, value)
	pows := computePows(pow, value)
	return append(intOuts, pows...)
}

func intPowCircuit(name string, nBits int, pow int) *circuit.Circuit {
	// Check that the first nBits are 0/1 values
	ckt := circuit.NBits(nBits, name)
	theInt := ckt.Outputs()[0]

	lp := logPow(pow)
	inps := make([]*circuit.Circuit, lp)
	for i := 0; i < lp; i++ {
		inps[i] = circuit.UncheckedInput(fmt.Sprintf("%v-pow", name))
	}

	// Ensure that each multiplication was done correctly
	checks := make([]*circuit.Circuit, lp)
	for i := 0; i < lp; i++ {
		powInt := inps[i].Outputs()[0]
		if i == 0 {
			checks[i] = circuit.CheckMul(theInt, theInt, powInt)
		} else {
			lastPowInt := inps[i-1].Outputs()[0]
			checks[i] = circuit.CheckMul(lastPowInt, lastPowInt, powInt)
		}
	}

	allCkts := make([]*circuit.Circuit, 0)
	allCkts = append(allCkts, ckt)
	allCkts = append(allCkts, inps...)
	allCkts = append(allCkts, checks...)

	return circuit.AndCircuits(allCkts)
}
