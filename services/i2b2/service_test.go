package serviceI2B2_test

import (
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/services/i2b2"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"strconv"
	"testing"
)

func getParam(nbHosts int, nbQp int) (abstract.Scalar, abstract.Point, *onet.Roster, *onet.LocalTest,
	[]*serviceI2B2.API, lib.CipherVector) {

	log.SetDebugVisible(1)
	local := onet.NewLocalTest()
	// generate 3 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(nbHosts, true)

	secKey := network.Suite.Scalar().Pick(random.Stream)
	pubKey := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)

	// Send a request to the service
	clients := make([]*serviceI2B2.API, nbHosts)
	for i := 0; i < nbHosts; i++ {
		clients[i] = serviceI2B2.NewUnLynxClient(el.List[i], strconv.Itoa(i))
	}

	// get query parameters
	return secKey, pubKey, el, local, clients, getQueryParams(nbQp, el.Aggregate)
}

func getQueryParams(nbQp int, encKey abstract.Point) lib.CipherVector {
	listQueryParameters := make(lib.CipherVector, 0)

	for i := 0; i < nbQp; i++ {
		listQueryParameters = append(listQueryParameters, *lib.EncryptInt(encKey, int64(i)))
	}

	return listQueryParameters
}

func TestServiceDDT(t *testing.T) {
	// test the query DDT with 100 query terms
	_, _, el, local, clients, qt := getParam(3, 100)
	defer local.CloseAll()

	proofs := false

	var result_node1, result_node1_repeated, result_node2, result_node3 []lib.GroupingKey

	wg := lib.StartParallelize(len(el.List))

	// the first two threads execute the same operation (repetition) to check that in the end it yields the same result
	go func() {
		defer wg.Done()

		var err error
		_, result_node1, _, err = clients[0].SendSurveyDDTRequestTerms(el, serviceI2B2.SurveyID("testSurvey_node1"), qt, proofs)

		if err != nil {
			t.Fatal("Client", clients[0], " service did not start: ", err)
		}
	}()
	go func() {
		defer wg.Done()

		var err error
		_, result_node1_repeated, _, err = clients[0].SendSurveyDDTRequestTerms(el, serviceI2B2.SurveyID("testSurvey_node1_repeated"), qt, proofs)

		if err != nil {
			t.Fatal("Client", clients[0], " service did not start: ", err)
		}
	}()
	go func() {
		defer wg.Done()

		var err error
		_, result_node2, _, err = clients[1].SendSurveyDDTRequestTerms(el, serviceI2B2.SurveyID("testSurvey_node2"), qt, proofs)

		if err != nil {
			t.Fatal("Client", clients[1], " service did not start: ", err)
		}
	}()

	var err error
	_, result_node3, _, err = clients[2].SendSurveyDDTRequestTerms(el, serviceI2B2.SurveyID("testSurvey_node3"), qt, proofs)

	if err != nil {
		t.Fatal("Client", clients[2], " service did not start: ", err)
	}

	lib.EndParallelize(wg)

	assert.Equal(t, len(result_node1), len(qt))
	assert.Equal(t, len(result_node2), len(qt))
	assert.Equal(t, len(result_node3), len(qt))

	assert.Equal(t, result_node1, result_node1_repeated)

}
