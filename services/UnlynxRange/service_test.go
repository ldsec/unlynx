package UnlynxRange

import (
	"testing"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"unlynx/lib"
	"gopkg.in/dedis/crypto.v0/abstract"
)

var nbHost = 10
var nbServ = 50
type empty string

func TestServiceUnlynxRange(t *testing.T) {
	//log.SetDebugVisible(3)
	local := onet.NewLocalTest()

	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(nbServ, false)
	defer local.CloseAll()

	//Client private and public for keyswitch
	FinalDecrypterp,FinalDecrypterP := lib.GenKey()
	log.Lvl1(FinalDecrypterP,FinalDecrypterp)

	//the CA public which is supposed to be sum of private of Serv
	_,CAPublic := lib.GenKey()

	dataPro := make([]*API,nbHost)

	//init the clients
	for i,v:= range dataPro  {
		v = NewUnlynxRangeClient("DP")
		v.CAPublic = CAPublic
		v.EntryPoint = el.List[i%nbServ]
		dataPro[i] = v
	}

	sem := make(chan empty, len(dataPro))
	sem2 := make(chan empty, len(dataPro))

	for _,v := range dataPro {
		go func(roster *onet.Roster, point abstract.Point) {
			res, _ := v.SendRequest(roster, point)
			sem <- empty(res)
		}(el, FinalDecrypterP)


		go func(roster *onet.Roster, point abstract.Point) {
			res, _ := v.ExecuteProof(roster,string(<-sem))
			log.Lvl1(res)
			sem2 <- ""
		}(el, FinalDecrypterP)
			<-sem2

	}
}
