package UnlynxRange

import (

	"gopkg.in/dedis/onet.v1"
	"math/big"
	"github.com/fanliao/go-concurrentMap"
	"gopkg.in/dedis/onet.v1/network"
	"gopkg.in/dedis/onet.v1/log"
	"unlynx/lib"
	"gopkg.in/dedis/crypto.v0/abstract"
)

const ServiceName = "UnlynxRange"

type PublishSignatureByte struct {
	Public abstract.Point
	Signature [][]byte
}

type DataDP struct {
	Roster *onet.Roster
	RequestID []byte
}

type ServiceSig struct {
	RequestID []byte
	Signature PublishSignatureByte
	U 			int64
	L			int64
}


func init() {
	onet.RegisterNewService(ServiceName, NewService)
	network.RegisterMessage(&ServiceSig{})

}

type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor
	//
	Signatures []PublishSignatureByte
	Request *concurrent.ConcurrentMap
	AggData [][]*big.Int
	U int64
	L int64
	Count int64
}

func NewService(c *onet.Context) onet.Service {
	newUnlynxRange := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		Request: concurrent.NewConcurrentMap(),
		Count: -1,
	}

	if cerr := newUnlynxRange.RegisterHandler(newUnlynxRange.HandleRequest); cerr != nil {
		log.Fatal("Wrong Handler.", cerr)
	}

	//Let's say range are already known
	newUnlynxRange.U = int64(2)
	newUnlynxRange.L = int64(6)
	//Compute the signatures in bytes so that you can send them

	return newUnlynxRange
}

//Handle a request from a client by registering it and computing each the hash and sending them
func (s *Service) HandleRequest(requestFromDP *DataDP)(network.Message, onet.ClientError) {

	log.Lvl1("Handling")
	if requestFromDP == nil {
		return nil, nil
	}

	s.Signatures = make([]PublishSignatureByte,len(requestFromDP.Roster.List))
	for j:=0 ; j<len(requestFromDP.Roster.List);j++ {
		signature := lib.InitRangeProofSignature(s.U)
		sigStruct := PublishSignatureByte{Public: signature.Public, Signature: make([][]byte, len(signature.Signature))}
		for i := 0; i < len(signature.Signature); i++ {
			bin,err := signature.Signature[i].MarshalBinary()

			if err != nil {
				log.Lvl1("Error in serializing")
			}

			sigStruct.Signature[i] = bin
		}
		s.Signatures[j] = sigStruct
	}


	s.Request.Put(string(requestFromDP.RequestID),requestFromDP)
	log.Lvl1(s.ServerIdentity(), " uploaded response data for Request ", string(requestFromDP.RequestID))

	s.Count++
	//log.Lvl1("Sending ",ServiceSig{RequestID:requestFromDP.RequestID,U:s.U,L:s.L,Signature:s.Signature[s.Count]})
	return &ServiceSig{RequestID:requestFromDP.RequestID,U:s.U,L:s.L,Signature:s.Signatures[s.Count]},nil
}