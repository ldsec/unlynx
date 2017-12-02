package prio

import (
	"testing"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
)

func TestServicePrio(t *testing.T) {
	//log.SetDebugVisible(3)
	local := onet.NewLocalTest()

	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(5, false)
	defer local.CloseAll()

	client := NewPrioClient("TestClient")
	log.Lvl1(client.secretValue)
	log.Lvl1(el.List[0])
	res,_ := client.SendRequest(el)
	log.Lvl1(res)
	client.ExecuteRequest(el,res)

}
