package serviceI2B2_test

import (
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/services/i2b2"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"strconv"
	"testing"
	//"time"
)

func getParam(nbHosts int) (*onet.Roster, *onet.LocalTest) {

	log.SetDebugVisible(1)
	local := onet.NewLocalTest()
	// generate 3 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(nbHosts, true)

	// get query parameters
	return el, local
}

func getClients(nbHosts int, el *onet.Roster) []*serviceI2B2.API {
	clients := make([]*serviceI2B2.API, nbHosts)
	for i := 0; i < nbHosts; i++ {
		clients[i] = serviceI2B2.NewUnLynxClient(el.List[i], strconv.Itoa(i))
	}

	return clients
}

func getQueryParams(nbQp int, encKey abstract.Point) lib.CipherVector {
	listQueryParameters := make(lib.CipherVector, 0)

	for i := 0; i < nbQp; i++ {
		listQueryParameters = append(listQueryParameters, *lib.EncryptInt(encKey, int64(i)))
	}

	return listQueryParameters
}

func TestServiceDDT(t *testing.T) {
	el, local := getParam(3)
	clients := getClients(3, el)
	// test the query DDT with 100 query terms
	nbQp := 100
	qt := getQueryParams(nbQp, el.Aggregate)
	defer local.CloseAll()

	proofs := false

	var result_node1, result_node1_repeated, result_node2, result_node3 []lib.GroupingKey

	wg := lib.StartParallelize(len(el.List))

	// the first two threads execute the same operation (repetition) to check that in the end it yields the same result
	go func() {
		defer wg.Done()

		var err error
		_, result_node1, _, err = clients[0].SendSurveyDDTRequestTerms(el, serviceI2B2.SurveyID("testDDTSurvey_node1"), qt, proofs)

		if err != nil {
			t.Fatal("Client", clients[0], " service did not start: ", err)
		}
	}()
	go func() {
		defer wg.Done()

		var err error
		_, result_node1_repeated, _, err = clients[0].SendSurveyDDTRequestTerms(el, serviceI2B2.SurveyID("testDDTSurvey_node1_repeated"), qt, proofs)

		if err != nil {
			t.Fatal("Client", clients[0], " service did not start: ", err)
		}
	}()
	go func() {
		defer wg.Done()

		var err error
		_, result_node2, _, err = clients[1].SendSurveyDDTRequestTerms(el, serviceI2B2.SurveyID("testDDTSurvey_node2"), qt, proofs)

		if err != nil {
			t.Fatal("Client", clients[1], " service did not start: ", err)
		}
	}()

	var err error
	_, result_node3, _, err = clients[2].SendSurveyDDTRequestTerms(el, serviceI2B2.SurveyID("testDDTSurvey_node3"), qt, proofs)

	if err != nil {
		t.Fatal("Client", clients[2], " service did not start: ", err)
	}

	lib.EndParallelize(wg)

	assert.Equal(t, len(result_node1), len(qt))
	assert.Equal(t, len(result_node2), len(qt))
	assert.Equal(t, len(result_node3), len(qt))

	assert.Equal(t, result_node1, result_node1_repeated)

}

func TestServiceAgg(t *testing.T) {
	el, local := getParam(3)
	clients1 := getClients(3, el)
	clients2 := getClients(3, el)
	defer local.CloseAll()

	proofs := false

	secKey1, pubKey1 := lib.GenKey()
	secKey2, pubKey2 := lib.GenKey()
	secKey3, pubKey3 := lib.GenKey()

	aggregate1 := lib.EncryptInt(el.Aggregate, int64(2))
	aggregate2 := lib.EncryptInt(el.Aggregate, int64(1))
	aggregate3 := lib.EncryptInt(el.Aggregate, int64(3))

	aggregate4 := lib.EncryptInt(el.Aggregate, int64(4))
	aggregate5 := lib.EncryptInt(el.Aggregate, int64(5))
	aggregate6 := lib.EncryptInt(el.Aggregate, int64(6))

	var result_node1, result_node2, result_node3, result_node4, result_node5, result_node6 lib.CipherText

	wg := lib.StartParallelize(len(el.List) * 2)

	// the first two threads execute the same operation (repetition) to check that in the end it yields the same result
	// surveyID should be the same
	go func() {
		defer wg.Done()

		var err error
		_, result_node1, _, err = clients1[0].SendSurveyAggRequest(el, serviceI2B2.SurveyID("testAggSurvey1"), pubKey1, *aggregate1, proofs)

		if err != nil {
			t.Fatal("Client", clients1[0], " service did not start: ", err)
		}
	}()
	go func() {
		defer wg.Done()

		var err error
		_, result_node2, _, err = clients1[1].SendSurveyAggRequest(el, serviceI2B2.SurveyID("testAggSurvey1"), pubKey2, *aggregate2, proofs)

		if err != nil {
			t.Fatal("Client", clients1[1], " service did not start: ", err)
		}
	}()
	go func() {
		defer wg.Done()

		var err error
		_, result_node3, _, err = clients1[2].SendSurveyAggRequest(el, serviceI2B2.SurveyID("testAggSurvey1"), pubKey3, *aggregate3, proofs)

		if err != nil {
			t.Fatal("Client", clients1[2], " service did not start: ", err)
		}
	}()

	go func() {
		defer wg.Done()

		var err error
		_, result_node4, _, err = clients2[0].SendSurveyAggRequest(el, serviceI2B2.SurveyID("testAggSurvey2"), pubKey1, *aggregate4, proofs)

		if err != nil {
			t.Fatal("Client", clients2[0], " service did not start: ", err)
		}
	}()
	go func() {
		defer wg.Done()

		var err error
		_, result_node5, _, err = clients2[1].SendSurveyAggRequest(el, serviceI2B2.SurveyID("testAggSurvey2"), pubKey2, *aggregate5, proofs)

		if err != nil {
			t.Fatal("Client", clients2[1], " service did not start: ", err)
		}
	}()
	go func() {
		defer wg.Done()

		var err error
		_, result_node6, _, err = clients2[2].SendSurveyAggRequest(el, serviceI2B2.SurveyID("testAggSurvey2"), pubKey3, *aggregate6, proofs)

		if err != nil {
			t.Fatal("Client", clients2[2], " service did not start: ", err)
		}
	}()

	lib.EndParallelize(wg)

	// Check result
	listResults1 := make([]int64, 0)
	listResults1 = append(listResults1, lib.DecryptInt(secKey1, result_node1), lib.DecryptInt(secKey2, result_node2), lib.DecryptInt(secKey3, result_node3))

	assert.Contains(t, listResults1, int64(2))
	assert.Contains(t, listResults1, int64(1))
	assert.Contains(t, listResults1, int64(3))

	listResults2 := make([]int64, 0)
	listResults2 = append(listResults2, lib.DecryptInt(secKey1, result_node4), lib.DecryptInt(secKey2, result_node5), lib.DecryptInt(secKey3, result_node6))

	assert.Contains(t, listResults2, int64(4))
	assert.Contains(t, listResults2, int64(5))
	assert.Contains(t, listResults2, int64(6))

}
