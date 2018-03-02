package libunlynx

import (
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/suites"
)

// Suite defines the capabilities required by the lib package.
type Suite interface {
	kyber.Group
	kyber.Random
	kyber.HashFactory
	kyber.XOF
	kyber.XOFFactory
}

// SuiTe defines the Suite type/ curve (Ed25519, or other)
var SuiTe = suites.MustFind("Ed25519") // Use the edwards25519-curve

// ChooseSuite defines which suite to use for all the operations
func ChooseSuite(suiteName string) {
	SuiTe = suites.MustFind(suiteName)
}
