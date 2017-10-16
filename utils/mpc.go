package utils

import (
"log"
"math/big"

"github.com/henrycg/prio/circuit"
"github.com/henrycg/prio/config"
"github.com/henrycg/prio/share"
"github.com/henrycg/prio/triple"
	"encoding/json"
	"fmt"
)

var Default *config.Config

//default config from prio
func configInit() {
	var err error
	Default , err = Load([]byte(config_Mixed()))

	if err != nil {
		log.Fatalf("error: %v", err)
	}

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

func checkInt(f *config.Field) error {
	if f.IntBits <= 0 {
		return fmt.Errorf("Field of type int or intPow must have intBits > 0")
	}

	if f.IntBits > 64 {
		return fmt.Errorf("We only support up to 64-bit ints")
	}

	return nil
}


func RandomRequest(cfg *config.Config, leaderForReq int) []*ClientRequest {
	//utils.PrintTime("Initialize")
	//nf := len(cfg.Fields)
	ns := cfg.NumServers()
	prg := share.NewGenPRG(ns, leaderForReq)

	configInit()
	cfg = Default
	out := make([]*ClientRequest, ns)
	for s := 0; s < ns; s++ {
		out[s] = new(ClientRequest)
	}
	//utils.PrintTime("ShareData")

	//here is supposed to be vector of input
	inputs := make([]*big.Int, 0)

	//config your cicuit in function of the given config (default here)
	ckt := configToCircuit(cfg)

	//evaluate each wire in function of the given input
	ckt.Eval(inputs)

	// Generate sharings of the input wires and the multiplication gate wires
	ckt.ShareWires(prg)

	// Construct polynomials f, g, and h and share evaluations of h
	sharePolynomials(ckt, prg)

	triples := triple.NewTriple(share.IntModulus, ns)
	for s := 0; s < ns; s++ {
		out[s].Hint = prg.Hints(s)
		out[s].TripleShare = triples[s]
	}

	return out
}


func configToCircuit(cfg *config.Config) *circuit.Circuit {
	nf := len(cfg.Fields)
	ckts := make([]*circuit.Circuit, nf)

	for f := 0; f < nf; f++ {
		field := &cfg.Fields[f]
		switch field.Type {
		default:
			panic("Unexpected type!")
		case config.TypeInt:
			ckts[f] = int_Circuit(field.Name, int(field.IntBits))
		}
	}

	ckt := circuit.AndCircuits(ckts)
	return ckt
}