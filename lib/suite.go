package libunlynx

import (
	"go.dedis.ch/kyber/v3/suites"
)

// SuiTe in this case is the ed25519 curve
var SuiTe = suites.MustFind("Ed25519")
