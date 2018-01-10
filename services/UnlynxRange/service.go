package UnlynxRange

import (

	"gopkg.in/dedis/onet.v1"
	"math/big"
	"github.com/fanliao/go-concurrentMap"
	"gopkg.in/dedis/onet.v1/network"
	"gopkg.in/dedis/onet.v1/log"

	"bytes"
	"encoding/gob"
	"fmt"

	"encoding/base64"
	"gopkg.in/dedis/crypto.v0/abstract"
//	"github.com/dedis/paper_17_dfinity/pbc"
)

const ServiceName = "UnlynxRange"

type DataDP struct {
	Roster *onet.Roster
	RequestID []byte
}

type ServiceSig struct {
	RequestID []byte
	U 			int64
	L			int64
}
/*
type PublishSignatureByte struct {
	Pairing *pbc.Pairing
	Public	abstract.Point
	Signature [][]byte
}*/

func init() {
	onet.RegisterNewService(ServiceName, NewService)
	network.RegisterMessage(&ServiceSig{})
	gob.Register([]abstract.Point{})
}

type SX map[string]interface{}

type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor
	//
	Request *concurrent.ConcurrentMap
	AggData [][]*big.Int
	Map 	SX
	U int64
	L int64
	Count int64
}

func NewService(c *onet.Context) onet.Service {
	newUnlynxRange := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		Request: concurrent.NewConcurrentMap(),
		Count: -1,
		Map: make(SX),
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

	/*
	s.Signature = make([]PublishSignatureByte,len(requestFromDP.Roster.List))
	for j:=0 ; j<len(requestFromDP.Roster.List);j++ {
		signature := lib.InitRangeProofSignature(s.U)
		sigStruct := PublishSignatureByte{Pairing: signature.Pairing, Public: signature.Public, Signature: make([][]byte, len(signature.Signature))}
		//for i := 0; i < len(signature.Signature); i++ {
			data := ToGOB64(signature.Signature[0])
			p := FromGOB64(data)
			log.Lvl1(p)
			sigStruct.Signature[0] = data
		//}
		s.Signature[j] = sigStruct
	}*/
	points := make([]abstract.Point,2)
	points[0] = network.Suite.Point().Base()
	points[1] = network.Suite.Point().Null()
	s.Map["test"] = points
	log.Lvl1("Test" , ToGOB64(s.Map))
	log.Lvl1( "GOBACK", FromGOB64("test"))

	s.Request.Put(string(requestFromDP.RequestID),requestFromDP)
	log.Lvl1(s.ServerIdentity(), " uploaded response data for Request ", string(requestFromDP.RequestID))

	s.Count++
	//log.Lvl1("Sending ",ServiceSig{RequestID:requestFromDP.RequestID,U:s.U,L:s.L,Signature:s.Signature[s.Count]})
	return &ServiceSig{RequestID:requestFromDP.RequestID,U:s.U,L:s.L},nil
}


// go binary encoder
func ToGOB64(m SX) string {
	b := bytes.Buffer{}
	e := gob.NewEncoder(&b)
	err := e.Encode(m)
	if err != nil { fmt.Println(`failed gob Encode`, err) }
	return base64.StdEncoding.EncodeToString(b.Bytes())
}

// go binary decoder
func FromGOB64(str string) SX {
	m := SX{}
	by, err := base64.StdEncoding.DecodeString(str)
	if err != nil { fmt.Println(`failed base64 Decode`, err); }
	b := bytes.Buffer{}
	b.Write(by)
	d := gob.NewDecoder(&b)
	err = d.Decode(&m)
	if err != nil { fmt.Println(`failed gob Decode`, err); }
	return m
}