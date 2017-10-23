package protocols

import (
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
	"errors"
	"gopkg.in/dedis/onet.v1/log"
	"math/big"
	"unlynx/prio_utils"
	"time"

	"fmt"
	"golang.org/x/crypto/nacl/box"
	"encoding/gob"
	"bytes"
	"github.com/henrycg/prio/utils"
)


const SumCipherProtocolName = "SumCipher"


/*Messages
____________________________________________________________________________________________________________________
 */

 //structure to announce start of protocol
type AnnounceSumCipher struct {
}

//Reply from the children
type ReplySumCipherBytes struct {
	Bytes []byte
}

type ReplySumCipherLength struct {
	BigIntLen int
	BitLen int
}
/*Structs
_________________________________________________________________________________________________________________________
*/

type StructAnnounce struct {
	*onet.TreeNode
	AnnounceSumCipher
}


type StructReply struct {
	*onet.TreeNode
	ReplySumCipherBytes
}


type Cipher struct {
	Share *big.Int

	//for the moment put bit in int
	Bits []uint
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
	check *prio_utils.Checker
	flag  StatusFlag
}


type EvalCircuitArgs struct {
	RequestID prio_utils.Uuid
}

type FinalCircuitArgs struct {
	RequestID prio_utils.Uuid
	Cor       *prio_utils.Cor
	Key       *utils.PRGKey
}

type AcceptArgs struct {
	RequestID prio_utils.Uuid
	Accept    bool
}

type AcceptReply struct {
}

type SumCipherProtocol struct {
	*onet.TreeNodeInstance

	//the feedback final
	Feedback chan *big.Int

	//Channel for up and down communication
	ChildDataChannel chan []StructReply

	AnnounceChannel chan StructAnnounce

	//The data of the protocol
	Ciphers []Cipher
	Sum 	*big.Int
	Modulus *big.Int

	//for proofs
	Args	*prio_utils.UploadArgs
	pool []* prio_utils.CheckerPool
	pending      map[prio_utils.Uuid]*RequestStatus
	pre          []*prio_utils.CheckerPrecomp
	randomX      []*big.Int
	Proofs  bool
	cfg          *prio_utils.Config
}
/*
_______________________________________________________________________________
 */

func init() {
	network.RegisterMessage(AnnounceSumCipher{})
	network.RegisterMessage(ReplySumCipherBytes{})
	onet.GlobalProtocolRegister(SumCipherProtocolName,NewSumCipherProtocol)
}


func NewSumCipherProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance,error) {

	st := &SumCipherProtocol{
		TreeNodeInstance: n,
		Feedback: make(chan *big.Int),
		Sum: big.NewInt(int64(0)),
		pending : make(map[prio_utils.Uuid]*RequestStatus),
	}

	//register the channel for announce
	err := st.RegisterChannel(&st.AnnounceChannel)
	if err != nil {
		return nil, errors.New("couldn't register Announce data channel: " + err.Error())
	}

	//register the channel for child response
	err = st.RegisterChannel(&st.ChildDataChannel)
	if err != nil {
		return nil, errors.New("couldn't register Child Response channel" + err.Error())
	}

	return st,nil
}

//start called at the root
func (p*SumCipherProtocol) Start() error {
	if p.Ciphers == nil {
			return errors.New("No Shares to collect")
	}
	log.Lvl1(p.ServerIdentity(), " started a Sum Cipher Protocol (", len(p.Ciphers), " different shares)")

	start := time.Now()
	//send to the children of the root
	p.SendToChildren(&AnnounceSumCipher{})
	log.Lvl1("time to send mesage to children of root ", time.Since(start))
	return nil
	}
//dispatch is called on the node and handle incoming messages

func (p*SumCipherProtocol) Dispatch() error {

	//Go down the tree
	if !p.IsRoot() {
		p.sumCipherAnnouncementPhase()
	}

	//Ascending aggreg
	start := time.Now()
	sum := p.ascendingAggregationPhase()
	log.Lvl1(p.ServerIdentity(), " completed aggregation phase (", sum, " is the sum ) in ", time.Since(start))

	//report result
	if p.IsRoot() {
		p.Feedback <-sum
	}
	return nil
}

func (p *SumCipherProtocol) sumCipherAnnouncementPhase() {
	//send down the tree if you have some
	AnnounceMessage := <-p.AnnounceChannel
	if !p.IsLeaf() {
		p.SendToChildren(&AnnounceMessage.AnnounceSumCipher)
	}
}

// Results pushing up the tree containing aggregation results.
func (p *SumCipherProtocol) ascendingAggregationPhase() *big.Int {

	if p.Ciphers == nil {
		p.Sum = big.NewInt(0)
	}

	if !p.IsLeaf() {
		//wait on the channel for child to complete and add sum
		for _, v := range <-p.ChildDataChannel {
			//get the bytes and turn them back in big.Int
			var sum big.Int
			sum.SetBytes(v.Bytes)
			p.Sum.Add(p.Sum, &sum)
			p.Sum.Mod(p.Sum,p.Modulus)
		}
	}

	//do the sum of ciphers

	for _, v := range p.Ciphers {
		if !Verify(v) {
			log.Lvl1("Share refused, will not use it for the operation ")
		} else {
			p.Sum.Add(p.Sum, Decode(v))
			p.Sum.Mod(p.Sum, p.Modulus)
		}
	}

	if p.Proofs{
		serverNumber := p.Tree().Size()
		c := make(chan error, serverNumber)

		newReqArgs := make([]prio_utils.NewRequestArgs, serverNumber)
		for s := 0; s < serverNumber; s++ {
			newReqArgs[s].RequestID = p.Args.PublicKey
			newReqArgs[s].Ciphertext = p.Args.Ciphertexts[s]
		}

		newReqReplies := make([]prio_utils.NewRequestReply, serverNumber)

		for i := 0; i < serverNumber; i++ {
			go func(j int) {
				c <- NewRequest( p, &newReqArgs[j], &newReqReplies[j])
			}(i)
		}
		uuid := p.Args.PublicKey
		v, ok := p.pending[uuid]
		check := v.check
		if !ok {
			log.Fatal("Should never get here")
		}


		c = make(chan error, serverNumber)

			var evalCircuitArgs *EvalCircuitArgs
			evalCircuitArgs.RequestID = uuid

			evalReplies := make([]*prio_utils.CorShare, serverNumber)

			for i := 0; i < serverNumber; i++ {
			go func(j int) {
			c <- EvalCircuit(p, evalCircuitArgs, evalReplies[j])
		}(i)
		}

		c = make(chan error, serverNumber)

		var finalCircuitArgs FinalCircuitArgs
		finalCircuitArgs.RequestID = uuid
		finalCircuitArgs.Cor = check.Cor(evalReplies)
		finalCircuitArgs.Key = utils.RandomPRGKey()

		finalReplies := make([]*prio_utils.OutShare, serverNumber)
		for i := 0; i < serverNumber; i++ {
			go func(j int) {
			c <- FinalCircuit(p, &finalCircuitArgs, finalReplies[j])
		}(i)
		}

		c = make(chan error, serverNumber)

		var acceptArgs AcceptArgs
		acceptArgs.RequestID = uuid
		acceptArgs.Accept = check.OutputIsValid(finalReplies)
		if !acceptArgs.Accept {
			log.Printf("Warning: rejecting request with ID %v", uuid)
		}

		/*if acceptArgs.Accept {
			l.lastRequestMutex.Lock()
			l.lastRequest++
			l.lastRequestMutex.Unlock()
		}*/

		acceptReplies := make([]AcceptReply, serverNumber)
		for i := 0; i < serverNumber; i++ {
			go func(j int) {
				c <- Accept(p, &acceptArgs, &acceptReplies[j])
			}(i)
		}

		}

	//send to parent the sum to deblock channel wait
	if !p.IsRoot() {
		//send the big.Int in bytes
		p.SendToParent(&ReplySumCipherBytes{p.Sum.Bytes()})
	}

	//finish by returning the sum of the root
	p.Sum.Mod(p.Sum,p.Modulus)
	return p.Sum
}


func Share(mod *big.Int, nPieces int, secret *big.Int) []*big.Int {

	if nPieces == 0 {
		panic("Number of shares must be at least 1")
	} else if nPieces == 1 {
		return []*big.Int{secret}
	}

	out := make([]*big.Int, nPieces)

	acc := new(big.Int)
	for i := 0; i < nPieces-1; i++ {
		out[i] = prio_utils.RandInt(mod)
		acc.Add(acc, out[i])
	}

	acc.Sub(secret, acc)
	acc.Mod(acc, mod)
	out[nPieces-1] = acc

	return out
}


func Encode(x *big.Int) (Cipher) {
	length := x.BitLen()
	resultBit := make([]uint,length)
	for i := 0; i < length; i++ {
		resultBit[i] = x.Bit(i)
	}
	cipher := Cipher{x,resultBit}
	return cipher
}

func Verify(c Cipher) (bool) {
	verify := big.NewInt(0)
	for i,b := range c.Bits {
		if b>1 || b<0 {
			panic("Not bits form in the encoding")
			return false
		}
		verify.Add(verify,big.NewInt(0).Mul(big.NewInt(int64(b)),big.NewInt(0).Exp(big.NewInt(2),big.NewInt(int64(i)),nil)))

	}
	difference := big.NewInt(int64(0))
	difference.Sub(c.Share,verify)
	if difference.Uint64()== uint64(0) {
		return true
	}
	errors.New(" The share is not equal to it's bit form")
	return false
}

func Decode(c Cipher)(x *big.Int) {
	return c.Share
}

func NewRequest(p *SumCipherProtocol,args *prio_utils.NewRequestArgs, reply *prio_utils.NewRequestReply) error {
	// Add request to queue
	r, err := decryptRequest(p.Index(), &args.RequestID, &args.Ciphertext)
	if err != nil {
		log.Print("Could not decrypt insert args")
		return err
	}

	dstServer := int(args.RequestID[0]) % p.Tree().Size()

	/*s.pendingMutex.RLock()
	exists := s.pending[args.RequestID] != nil
	s.pendingMutex.RUnlock()

	if exists {
		log.Print(s.pending[args.RequestID])
		log.Print("Error: Key collision! Ignoring bogus request.")
		return nil
	}*/
	status := new(RequestStatus)
	fmt.Println(dstServer,r,status)
	return nil

}

func EvalCircuit(p *SumCipherProtocol,args *EvalCircuitArgs, reply *prio_utils.CorShare) error {
	leader := prio_utils.HashToServer(p.cfg, args.RequestID)

	//s.pendingMutex.RLock()
	status, okay := p.pending[args.RequestID]
	//s.pendingMutex.RUnlock()
	if !okay {
		return errors.New("Could not find specified request")
	}

	if status.flag != NotStarted {
		return errors.New("Request already processed")
	}

	if p.randomX[leader] != nil {
		p.pre[leader].SetCheckerPrecomp(p.randomX[leader])
	}
	p.randomX[leader] = nil


	status.flag = Layer1
	status.check.CorShare(reply, p.pre[leader])

	//log.Print("Done evaluating ", args.RequestID)
	return nil
}

func FinalCircuit(p *SumCipherProtocol,args *FinalCircuitArgs, reply *prio_utils.OutShare) error {

	//s.pendingMutex.RLock()
	status, okay := p.pending[args.RequestID]
	//s.pendingMutex.RUnlock()
	if !okay {
		return errors.New("Could not find specified request")
	}

	if status.flag != Layer1 {
		return errors.New("Request already processed")
	}
	status.flag = Finished

	status.check.OutShare(reply, args.Cor, args.Key)

	return nil
}

func Accept(p *SumCipherProtocol,args *AcceptArgs, reply *AcceptReply) error {
	//s.pendingMutex.RLock()
	status, okay := p.pending[args.RequestID]
	//s.pendingMutex.RUnlock()
	if !okay {
		return errors.New("Could not find specified request")
	}

	if status.flag != Finished {
		return errors.New("Request not yet processed")
	}

	//s.pendingMutex.Lock()
	delete(p.pending, args.RequestID)
	//s.pendingMutex.Unlock()

	//l := prio_utils.HashToServer(p.cfg, args.RequestID)
	if args.Accept {
		//s.aggMutex[l].Lock()
		//p.agg[l].Update(status.check)
		//s.aggMutex[l].Unlock()

		//s.nProcessedCond[l].Signal()
		//s.nProcessedMutex[l].Lock()
		//s.nProcessed[l]++
		//s.nProcessedMutex[l].Unlock()
		//s.nProcessedCond[l].Signal()
	}

	//log.Printf("Done!")
	//p.pool[l].put(status.check)

	return nil
}



func decryptRequest(serverIdx int, requestID *prio_utils.Uuid, enc *prio_utils.ServerCiphertext) (*prio_utils.ClientRequest, error) {
	serverPrivateKey := utils.ServerBoxPrivateKeys[serverIdx]
	clientPublicKey := (*[32]byte)(requestID)

	var buf []byte
	buf, okay := box.Open(nil, enc.Ciphertext, &enc.Nonce,
		clientPublicKey, serverPrivateKey)

	query := new(prio_utils.ClientRequest)
	if !okay {
		return query, errors.New("Could not decrypt")
	}

	dec := gob.NewDecoder(bytes.NewBuffer(buf))
	err := dec.Decode(&query)
	if err != nil {
		return query, err
	}

	return query, nil

}