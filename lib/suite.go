package libunlynx

import (
	"github.com/dedis/kyber/suites"
)

// SuiTe in this case is the ed25519 curve
var SuiTe = suites.MustFind("Ed25519")
