package utils

import (
	"math/big"
	"github.com/henrycg/prio/share"
	"github.com/henrycg/prio/triple"
	"github.com/henrycg/prio/circuit"
	"golang.org/x/crypto/nacl/box"
	"crypto/rand"
)

//this should be run at client for proof start
//a ClientRequest is sent to each server from one client, for all client
type Config struct {
	Circuit        *circuit.Circuit
	//data to send
	Data         []*big.Int
	//num of server
	Servers        int
	//Modulus
	Modulus			*big.Int
}


//This is to make ClientRequest from the config and leader
func Request(cfg *Config, leaderForReq int) []*ClientRequest {
	//utils.PrintTime("Initialize")
	//nf := len(cfg.Fields)
	ns := cfg.Servers
	prg := share.NewGenPRG(ns, leaderForReq)

	out := make([]*ClientRequest, ns)
	for s := 0; s < ns; s++ {
		out[s] = new(ClientRequest)
	}
	//config your cicuit in function of the given config (default here)
	ckt := configToCircuit(cfg)

	//TODO : NEED To create method to change modulus
	//ckt.setMod(cfg.Modulus)

	//evaluate each wire in function of the given input
	ckt.Eval(cfg.Data)

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


//this to generate the argument to upload to the server
func GenUploadArgs(cfg *Config, leaderIdx int, reqs []*ClientRequest) (*UploadArgs, error) {
	n := cfg.Servers

	out := new(UploadArgs)
	var err error
	var pub, priv *[32]byte

	for {
		pub, priv, err = box.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}

		if HashToServer(cfg, *pub) == leaderIdx || leaderIdx < 0 {
			break
		}
	}

	leaderForReq := HashToServer(cfg, *pub)
	if reqs == nil {
		reqs = Request(cfg, leaderForReq)
	}

	out.PublicKey = *pub
	out.Ciphertexts = make([]ServerCiphertext, n)
	for s := 0; s < n; s++ {

		out.Ciphertexts[s], err = encryptRequest(pub, priv, s, reqs[s])

		if err != nil {
			return nil, err
		}
	}

	return out, nil
}

