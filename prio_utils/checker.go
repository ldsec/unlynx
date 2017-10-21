package prio_utils

import (
	"math/big"
	"github.com/henrycg/prio/share"
	"github.com/henrycg/prio/circuit"
)

type Checker struct {
	cfg *Config
	req *ClientRequest
	prg *share.ReplayPRG

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

func (c *Checker) SetReq(req *ClientRequest) {
	c.req = req
	c.prg.Import(req.Hint)

	// Reconstruct shares of internal wires using
	// client-provided values.
	c.ckt.ImportWires(c.prg)
}