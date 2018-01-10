package UnlynxRange

import (
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/crypto.v0/abstract"
	"unlynx/lib"
	"github.com/dedis/paper_17_dfinity/pbc"
)

//data provider in prio represented as its secret value ID and modulus
type API struct {
	*onet.Client
	ClientID   string
	secretValue []int64
	ToPublish	[][]lib.PublishRangeProof
}

func NewUnlynxRangeClient(clientID string) *API {

	newClient := &API{
		Client:     onet.NewClient(ServiceName),
		ClientID:   clientID,
		secretValue:  []int64{2,16,154816,1,18946,48918896418965},
	}
	return newClient
}


func (c *API) SendRequest(entities *onet.Roster)(string, error) {
	servList := entities.List

	//structure response and pairing used
	sig := ServiceSig{}
	pairing := pbc.NewPairingFp254BNb()
	c.ToPublish = make([][]lib.PublishRangeProof,len(servList))

	for i:=0;i<len(servList) ;i++  {
		//send server that you need the signature
		c.SendProtobuf(servList[i],&DataDP{Roster:entities,RequestID:[]byte("test")},&sig)
		log.Lvl1("Receiving ", sig)
		//here need to get back signature that were transferred in bytes
		signatureStruct := lib.PublishSignature{Public:sig.Signature.Public,Signature:make([]abstract.Point,len(sig.Signature.Signature))}
		for i:=0;i<len(sig.Signature.Signature);i++ {
			point := pairing.G1().Point()
			err := point.UnmarshalBinary(sig.Signature.Signature[i])
			if err != nil {
				log.Fatal("Cannot deserialize")
			}
			signatureStruct.Signature[i] = point
		}
		//For each server, and each secret you have , compute the predicate for proving secret_k
		//is in the range given. Each server will verify it.
		c.ToPublish[i][0] = lib.CreatePredicateRangeProof(signatureStruct,sig.U,sig.L,c.secretValue[0],signatureStruct.Public)

	}
	//return the id of the request in the concurrent map of service if successful
	return string(sig.RequestID), nil
}



func (c *API) ExecuteRequest(entities *onet.Roster,id string)(error) {

	for i,v := range entities.List {
		err := c.SendProtobuf(v, &c.ToPublish[i][0], &result)

		if err != nil {
			return  err
		}
	}
	return nil
}