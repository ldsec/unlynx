package utils

import (
	"math/big"
	"github.com/henrycg/prio/poly"
	"github.com/henrycg/prio/utils"
	"github.com/henrycg/prio/circuit"
	"github.com/henrycg/prio/share"
	"gopkg.in/dedis/onet.v1/log"
	"encoding/json"
	"github.com/henrycg/prio/config"
	"fmt"
)


func checkInt(f *config.Field) error {
	if f.IntBits <= 0 {
		return fmt.Errorf("Field of type int or intPow must have intBits > 0")
	}

	if f.IntBits > 64 {
		return fmt.Errorf("We only support up to 64-bit ints")
	}

	return nil
}


func Load(s []byte) (*config.Config, error) {
	cfg := new(config.Config)

	// XXX Here for now
	//cfg.Fields = make([]Field, 0)
	err := json.Unmarshal(s, &cfg)
	if err != nil {
		return nil, err
	}

	if cfg.MaxPendingReqs == 0 {
		cfg.MaxPendingReqs = DEFAULT_MAX_PENDING_REQS
	}

	for i := 0; i < len(cfg.Fields); i++ {
		f := &cfg.Fields[i]
		switch f.Type {
		case config.TypeInt:
			err = checkInt(f)
		}
		if err != nil {
			return nil, err
		}
	}
	return cfg, err
}

func sharePolynomials(ckt *circuit.Circuit, prg *share.GenPRG) {
	mulGates := ckt.MulGates()
	mod := ckt.Modulus()

	// Little n the number of points on the polynomials.
	// The constant term is randomized, so it's (mulGates + 1).
	n := len(mulGates) + 1
	log.Printf("Mulgates: %v", n)

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


func HashToServer(cfg *Config, uuid Uuid) int {
	return int(uuid[0]) % cfg.Servers
}