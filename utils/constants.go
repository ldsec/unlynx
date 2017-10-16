package utils

import (
	"github.com/henrycg/prio/share"
	"github.com/henrycg/prio/triple"
	"github.com/henrycg/prio/config"
)

func config_Mixed() string {
	return `{
    "servers": [
      {"addrPub": "localhost:9000", "addrPriv": "localhost:9050"},
      {"addrPub": "localhost:9001", "addrPriv": "localhost:9051"},
      {"addrPub": "localhost:9002", "addrPriv": "localhost:9052"},
      {"addrPub": "localhost:9003", "addrPriv": "localhost:9053"},
      {"addrPub": "localhost:9004", "addrPriv": "localhost:9054"}
    ],
    "fields": [
      {"name": "val0", "type": "int", "intBits": 4},
      {"name": "bool0", "type": "boolOr"},
      {"name": "bool1", "type": "boolAnd"},
      {"name": "unsafe0", "type": "intUnsafe", "intBits": 5},
      {"name": "pow0", "type": "intPow", "intPow": 4, "intBits": 3},
			{"name": "sketch", "type": "countMin",
	       "countMinBuckets": 32,
	       "countMinHashes": 8},
			{"name": "linReg0", "type": "linReg",
	        "linRegBits": [2,3,4,5,6]}
    ]
  }`
}

const DEFAULT_MAX_PENDING_REQS = 64



// The data struct that the client gives to each server.
type ClientRequest struct {
	Hint *share.PRGHints

	// Compressed representation of Beaver triples for the
	// batch checking and for the main MPC protocol.
	TripleShare *triple.Share
}
