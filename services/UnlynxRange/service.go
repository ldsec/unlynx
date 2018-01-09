package UnlynxRange

import (

	"gopkg.in/dedis/onet.v1"
	"math/big"
	"github.com/fanliao/go-concurrentMap"
	"crypto/x509"
	"gopkg.in/dedis/crypto.v0/abstract"
)

const ServiceName = "UnlynxRange"

type DataDP struct {
	Roster *onet.Roster
	RequestID []byte
}

type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor
	//
	Request *concurrent.ConcurrentMap
	AggData [][]*big.Int
	Private	abstract.Scalar
	Public abstract.Point
	Signature []abstract.Point
	U int64
	L int64
	Count int64
}

func NewService(c *onet.Context) onet.Service {
	newUnlynxRange := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		Request: concurrent.NewConcurrentMap(),
	}

	return newUnlynxRange
}