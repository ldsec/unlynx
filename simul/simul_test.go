package main_test

import (
	"testing"

	"github.com/dedis/onet/log"
	"github.com/dedis/onet/simul"
)

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestSimulation(t *testing.T) {
	simul.Start("runfiles/addrm_server.toml", "runfiles/collective_aggregation.toml", "runfiles/deterministic_tagging.toml", "runfiles/key_switching.toml",
		"runfiles/local_aggregation.toml", "runfiles/local_clear_aggregation.toml", "runfiles/proofs_verification.toml", "runfiles/shuffling.toml", "runfiles/unlynx_default.toml")
}
