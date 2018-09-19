package libunlynx

import (
	"github.com/dedis/cothority"
	"github.com/dedis/kyber/suites"
)

// SuiTe is the instantiation of the suite
// var SuiTe = bn256.NewSuiteG1()

func init() {
	cothority.Suite = SuiTe
}

// SuiTe in this case is the ed25519 curve
var SuiTe = suites.MustFind("Ed25519")

//var SuiTe = suites.MustFind("bn256.g1")

//func CurvePairingTest() bool {
//	return SuiTe.String() == "combined:bn256.G1"
//}
