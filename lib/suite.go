package libunlynx

import (
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/suites"
)

// SuiteT defines the capabilities required by the lib package.
type Suite interface {
	kyber.Group
	kyber.Random
	kyber.HashFactory
	kyber.XOF
	kyber.XOFFactory
}

// SuiteT defines the Suite type/ curve (Ed25519, or other)
var SuiteT = suites.MustFind("Ed25519") // Use the edwards25519-curve
