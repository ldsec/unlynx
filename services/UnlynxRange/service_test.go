package UnlynxRange

import (
	"testing"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"unlynx/lib"
)

func TestServiceUnlynxRange(t *testing.T) {
	//log.SetDebugVisible(3)
	local := onet.NewLocalTest()

	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(5, false)
	defer local.CloseAll()

	FinalDecrypterp,FinalDecrypterP := lib.GenKey()
	log.Lvl1(FinalDecrypterP,FinalDecrypterp)

	client := NewUnlynxRangeClient("Client")
	client2 := NewUnlynxRangeClient("Client")
	_,client.CAPublic = lib.GenKey()
	client.EntryPoint = el.List[0]
	client2.CAPublic = client.CAPublic
	client2.EntryPoint = el.List[1]

	res,_ := client.SendRequest(el,FinalDecrypterP)
	log.Lvl1(res)
	resu,err := client.ExecuteProof(el,res)
	log.Lvl1(resu,err)
	res2,_ := client2.SendRequest(el,FinalDecrypterP)
	log.Lvl1(res2)
	resu2,err := client2.ExecuteProof(el,res2)
	log.Lvl1(resu2)
	//client.ExecuteRequest(el,res)

}
