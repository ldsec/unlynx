package main

import (
	"os"

	"github.com/LCA1/UnLynx/lib"
	"github.com/LCA1/UnLynx/services/default"
	"github.com/btcsuite/goleveldb/leveldb/errors"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/app"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/urfave/cli.v1"
	"regexp"
	"strconv"
	"strings"
)

// BEGIN CLIENT: QUERIER ----------
func startQuery(el *onet.Roster, proofs bool, sum []string, count bool, whereQueryValues []lib.WhereQueryAttribute, predicate string, groupBy []string) {
	client := serviceDefault.NewUnLynxClient(el.List[0], strconv.Itoa(0))

	// Generate Survey Data
	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	for _, server := range el.List {
		nbrDPs[server.String()] = 1 // 1 DP for each server
	}

	surveyID, err := client.SendSurveyCreationQuery(el, serviceDefault.SurveyID(""), nil, nbrDPs, proofs, true, sum, count, whereQueryValues, predicate, groupBy)
	if err != nil {
		log.Fatal("Service did not start.", err)
	}

	grp, aggr, err := client.SendSurveyResultsQuery(*surveyID)
	if err != nil {
		log.Fatal("Service could not output the results.")
	}

	// Print Output
	log.LLvl1("Service output:")
	var tabVerify [][]int64
	tabVerify = *grp
	for i := range tabVerify {
		log.LLvl1(i, ")", (*grp)[i], "->", (*aggr)[i])
	}
}

func runUnLynx(c *cli.Context) error {
	tomlFileName := c.String("file")

	proofs := c.Bool("proofs")

	// query parameters
	sum := c.String("sum")
	count := c.Bool("count")
	whereQueryValues := c.String("where")
	predicate := c.String("predicate")
	groupBy := c.String("groupBy")

	el, err := openGroupToml(tomlFileName)
	if err != nil {
		return err
	}

	sumFinal, countFinal, whereFinal, predicateFinal, groupByFinal := parseQuery(el, sum, count, whereQueryValues, predicate, groupBy)
	startQuery(el, proofs, sumFinal, countFinal, whereFinal, predicateFinal, groupByFinal)

	return nil
}

func openGroupToml(tomlFileName string) (*onet.Roster, error){
	f, err := os.Open(tomlFileName)
	if err != nil {
		return nil, err
	}
	el, err := app.ReadGroupToml(f)
	if err != nil {
		return nil, err
	}

	if len(el.List) <= 0 {
		return nil, errors.New("Empty or invalid unlynx group file:" + tomlFileName)
	}

	return el, nil
}

func checkRegex(input, expression, errorMessage string) {
	var aux = regexp.MustCompile(expression)

	correct := aux.MatchString(input)

	if !correct {
		log.Fatal(errorMessage)
	}
}

func parseQuery(el *onet.Roster, sum string, count bool, where, predicate, groupBy string) ([]string, bool, []lib.WhereQueryAttribute, string, []string) {

	if sum == "" || (where != "" && predicate == "") || (where == "" && predicate != "") {
		log.Fatal("Wrong query! Please check the sum, where and the predicate parameters")
	}

	sumRegex := "{s[0-9]+(,\\s*s[0-9]+)*}"
	whereRegex := "{(w[0-9]+(,\\s*[0-9]+))*(,\\s*w[0-9]+(,\\s*[0-9]+))*}"
	groupByRegex := "{g[0-9]+(,\\s*g[0-9]+)*}"

	checkRegex(sum, sumRegex, "Error parsing the sum parameter(s)")
	sum = strings.Replace(sum, " ", "", -1)
	sum = strings.Replace(sum, "{", "", -1)
	sum = strings.Replace(sum, "}", "", -1)
	sumFinal := strings.Split(sum, ",")

	if count {
		check := false
		for _, el := range sumFinal {
			if el == "count" {
				check = true
			}
		}

		if !check {
			log.Fatal("No 'count' attribute in the sum variables")
		}
	}

	checkRegex(where, whereRegex, "Error parsing the where parameter(s)")
	where = strings.Replace(where, " ", "", -1)
	where = strings.Replace(where, "{", "", -1)
	where = strings.Replace(where, "}", "", -1)
	tmp := strings.Split(where, ",")

	whereFinal := make([]lib.WhereQueryAttribute, 0)

	var variable string
	for i := range tmp {
		// if is a variable (w1, w2...)
		if i%2 == 0 {
			variable = tmp[i]
		} else { // if it is a value
			value, err := strconv.Atoi(tmp[i])
			if err != nil {
				log.Fatal("Something wrong with the where value")
			}

			whereFinal = append(whereFinal, lib.WhereQueryAttribute{Name: variable, Value: *lib.EncryptInt(el.Aggregate, int64(value))})
		}
	}

	checkRegex(groupBy, groupByRegex, "Error parsing the groupBy parameter(s)")
	groupBy = strings.Replace(groupBy, " ", "", -1)
	groupBy = strings.Replace(groupBy, "{", "", -1)
	groupBy = strings.Replace(groupBy, "}", "", -1)
	groupByFinal := strings.Split(groupBy, ",")

	return sumFinal, count, whereFinal, predicate, groupByFinal
}

// CLIENT END: QUERIER ----------
