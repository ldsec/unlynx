package main_test

import (
	"gopkg.in/dedis/onet.v1/simul"
	"testing"
)



func TestSimulation(t *testing.T) {
	simul.Start("runfiles/addrm_server.toml", "runfiles/collective_aggregation.toml", "runfiles/deterministic_tagging.toml", "runfiles/key_switching.toml",
		"runfiles/local_aggregation.toml", "runfiles/local_clear_aggregation.toml", "runfiles/proofs_verification.toml", "runfiles/shuffling.toml", "runfiles/unlynx.toml")
	//simul.Start("runfiles/prio_verification.toml","runfiles/prio_aggregation.toml")
	//simul.Start("runfiles/local_aggregation.toml","runfiles/collective_aggregation.toml")
	}
