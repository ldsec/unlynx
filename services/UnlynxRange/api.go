package UnlynxRange

import (
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
)

//data provider in prio represented as its secret value ID and modulus
type API struct {
	*onet.Client
	ClientID   string
	secretValue []int64
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
	sig := ServiceSig{}
	for i:=0;i<len(servList) ;i++  {
		c.SendProtobuf(servList[i],&DataDP{Roster:entities,RequestID:[]byte("test")},&sig)
		log.Lvl1("Receiving ", sig)
		//here need to compute the things for each signature
		//signatureStruct := lib.PublishSignature{Pairing:sig.Signature.Pairing,Public:sig.Signature.Public,Signature:make([]abstract.Point,len(sig.Signature.Signature))}

		//signatureStruct.Signature = lib.BytesToAbstractPoints(sig.Signature.Signature)
		//oPublishFromDp := lib.CreatePredicateRangeProof(signatureStruct,sig.U,sig.L,c.secretValue[0],signatureStruct.Public)
		//log.Lvl1(toPublishFromDp)
	}
	//return the id of the request in the concurrent map of service if successful
	//log.Lvl1(lib.BytesToAbstractPoints(sig.Signature.Signature))
	//lib.CreatePredicateRangeProof(sig.Signature,sig.U,sig.L,c.secretValue[0],sig.Signature.Public)
	return string(sig.RequestID), nil
}


/*
func (c *API) ExecuteRequest(entities *onet.Roster,id string)(error) {

	for _,v := range entities.List {
		err := c.SendProtobuf(v, &ExecRequest{id}, &result)

		if err != nil {
			return  err
		}
	}
	return nil
}*/