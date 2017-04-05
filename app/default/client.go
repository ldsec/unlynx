package main

import (
	"os"

	"github.com/btcsuite/goleveldb/leveldb/errors"
	"gopkg.in/codegangsta/cli.v1"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/app"
	"gopkg.in/dedis/onet.v1/log"
)

// BEGIN CLIENT: QUERIER ----------
func startQuery(el *onet.Roster, proofs bool) {
	/*client := medco.NewMedcoClient(el.List[0])

	// Generate Survey Data
	surveyDesc := lib.SurveyDescription{GroupingAttributesCount: int32(2), AggregatingAttributesCount: uint32(100)}
	surveyID, err := client.CreateSurvey(el, surveyDesc, !encryptedGroups, proofs, true)
	if err != nil {
		log.Fatal("Service did not start.", err)
	}

	grpClear, grp, aggr, err := client.GetSurveyResults(*surveyID)
	if err != nil {
		log.Fatal("Service could not output the results. ", err)
	}

	// Print Output
	all_data := make([]lib.ClientClearResponse, 0)
	log.Lvl1("Service output:")
	for i := range *grp {
		log.Lvl1(i, ")", (*grpClear)[i], ", ", (*grp)[i], "->", (*aggr)[i])
		if encryptedGroups {
			all_data = append(all_data, lib.ClientClearResponse{GroupingAttributes: (*grp)[i], AggregatingAttributes: (*aggr)[i]})
		} else {
			all_data = append(all_data, lib.ClientClearResponse{GroupingAttributes: (*grpClear)[i], AggregatingAttributes: (*aggr)[i]})
		}

	}*/
}

func runMedco(c *cli.Context) error {
	tomlFileName := c.String("group")

	proofs := c.Bool("proofs")

	// query parameters
	sum := c.StringSlice("sum")
	count := c.Bool("count")
	whereQueryValues := c.StringSlice("where")
	predicate := c.String("predicate")
	groupBy := c.StringSlice("groupBy")

	log.LLvl1(sum, count, whereQueryValues, predicate, groupBy)

	f, err := os.Open(tomlFileName)
	if err != nil {
		return err
	}
	el, err := app.ReadGroupToml(f)

	if err != nil {
		return err
	}
	if len(el.List) <= 0 {
		return errors.New("Empty or invalid medco group file:" + tomlFileName)
	}

	startQuery(el, proofs)

	return nil
}

// CLIENT END: QUERIER ----------
