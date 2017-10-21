package utils

import (
	"github.com/henrycg/prio/share"
	"github.com/henrycg/prio/triple"
	"math/big"
	"github.com/henrycg/prio/circuit"
	"github.com/henrycg/prio/config"
)

type Uuid [32]byte

const DEFAULT_MAX_PENDING_REQS = 64

// The data struct that the client gives to each server.
type ClientRequest struct {
	Hint *share.PRGHints

	// Compressed representation of Beaver triples for the
	// batch checking and for the main MPC protocol.
	TripleShare *triple.Share
}

type ServerCiphertext struct {
	Nonce      [24]byte // NaCl Box nonce
	Ciphertext []byte   // Encrypted upload payload
}

type UploadArgs struct {
	PublicKey   [32]byte // NaCl Box public key
	Ciphertexts []ServerCiphertext
}

type NewRequestArgs struct {
	RequestID  Uuid
	Ciphertext ServerCiphertext
}

type NewRequestReply struct {
}

type StatusFlag int

// Status of a client submission.
const (
	NotStarted    StatusFlag = iota
	OpenedTriples StatusFlag = iota
	Layer1        StatusFlag = iota
	Finished      StatusFlag = iota
)

type RequestStatus struct {
	check *Checker
	flag  StatusFlag
}

type CheckerPool struct {
	serverIdx int
	leaderIdx int
	buffer    chan Checker
}

type Checker struct {
	cfg *config.Config
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
