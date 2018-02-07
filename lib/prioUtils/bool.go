package prioUtils

import (
	"math/big"

	"github.com/henrycg/prio/circuit"
	"github.com/henrycg/prio/utils"
)

//File originally in Prio repository.
//Copied here to show whate can be done with each type.

type boolOp int

const (
	//OpOR is the OR
	OpOR boolOp = iota
	//OpAND is the AND
	OpAND boolOp = iota
)

func boolCircuit(name string) *circuit.Circuit {
	return circuit.UncheckedInput(name)
}

func boolNewRandom() []*big.Int {
	v := (utils.RandInt(big.NewInt(2)).Cmp(big.NewInt(0)) == 1)
	return boolNew(v)
}

func boolNew(value bool) []*big.Int {
	vInt := int64(0)
	if value {
		vInt = 1
	}

	return []*big.Int{big.NewInt(vInt)}
}
