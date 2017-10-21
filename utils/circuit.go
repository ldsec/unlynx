package utils

import (
	"github.com/henrycg/prio/circuit"
)

//take a config and for each Data, create a int circuit in function of the number of bit
//then do a AND of all circuit
func configToCircuit(cfg *Config) *circuit.Circuit {
	nf := len(cfg.Data)
	ckts := make([]*circuit.Circuit, nf)

	for f := 0; f < nf; f++ {
		ckts[f] = int_Circuit("int Field", int(cfg.Data[f].BitLen()))
		}

	ckt := circuit.AndCircuits(ckts)
	return ckt
}