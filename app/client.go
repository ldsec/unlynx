package appunlynx

import (
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/services"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/app"
	"go.dedis.ch/onet/v3/log"
	"gopkg.in/urfave/cli.v1"
)

// BEGIN CLIENT: QUERIER ----------
func startQuery(el *onet.Roster, proofs bool, sum []string, count bool, whereQueryValues []libunlynx.WhereQueryAttribute, predicate string, groupBy []string) error {
	client := servicesunlynx.NewUnLynxClient(el.List[0], strconv.Itoa(0))

	nbrDPs := make(map[string]int64)
	//how many data providers for each server
	for _, server := range el.List {
		nbrDPs[server.String()] = 1 // 1 DP for each server
	}

	surveyID, err := client.SendSurveyCreationQuery(el, servicesunlynx.SurveyID(""), nil, nbrDPs, proofs, true, sum, count, whereQueryValues, predicate, groupBy)
	if err != nil {
		return err
	}

	grp, aggr, err := client.SendSurveyResultsQuery(*surveyID)
	if err != nil {
		return errors.New("service could not output the results: " + err.Error())
	}

	// Print Output
	log.Lvl1("Service output:")
	var tabVerify [][]int64
	tabVerify = *grp
	for i := range tabVerify {
		log.Lvl1(i, ")", (*grp)[i], "->", (*aggr)[i])
	}
	return nil
}

func runUnLynx(c *cli.Context) {
	tomlFileName := c.String("file")

	proofs := c.Bool("proofs")

	// query parameters
	sum := c.String("sum")
	count := c.Bool("count")
	whereQueryValues := c.String("where")
	predicate := c.String("predicate")
	groupBy := c.String("groupBy")

	el, err := openGroupToml(tomlFileName)
	log.ErrFatal(err, "Could not open group toml.")

	sumFinal, countFinal, whereFinal, predicateFinal, groupByFinal, err := parseQuery(el, sum, count, whereQueryValues, predicate, groupBy)

	err = startQuery(el, proofs, sumFinal, countFinal, whereFinal, predicateFinal, groupByFinal)
	log.ErrFatal(err)
}

func openGroupToml(tomlFileName string) (*onet.Roster, error) {
	f, err := os.Open(tomlFileName)
	if err != nil {
		return nil, err
	}
	el, err := app.ReadGroupDescToml(f)
	if err != nil {
		return nil, err
	}

	if len(el.Roster.List) <= 0 {
		return nil, errors.New("empty or invalid unlynx group file:" + tomlFileName)
	}

	return el.Roster, nil
}

func checkRegex(input, expression string) bool {
	var aux = regexp.MustCompile(expression)
	return aux.MatchString(input)
}

func parseQuery(el *onet.Roster, sum string, count bool, where, predicate, groupBy string) ([]string, bool, []libunlynx.WhereQueryAttribute, string, []string, error) {

	if sum == "" || (where != "" && predicate == "") || (where == "" && predicate != "") {
		return nil, false, nil, "", nil, errors.New("wrong query! please check the sum, where and the predicate parameters")
	}

	sumRegex := "{s[0-9]+(,\\s*s[0-9]+)*}"
	whereRegex := "{(w[0-9]+(,\\s*[0-9]+))*(,\\s*w[0-9]+(,\\s*[0-9]+))*}"
	groupByRegex := "{g[0-9]+(,\\s*g[0-9]+)*}"

	if !checkRegex(sum, sumRegex) {
		return nil, false, nil, "", nil, errors.New("error parsing the sum parameter(s)")
	}
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
			return nil, false, nil, "", nil, errors.New("no 'count' attribute in the sum variables")
		}
	}

	if !checkRegex(where, whereRegex) {
		return nil, false, nil, "", nil, errors.New("error parsing the where parameter(s)")
	}
	where = strings.Replace(where, " ", "", -1)
	where = strings.Replace(where, "{", "", -1)
	where = strings.Replace(where, "}", "", -1)
	tmp := strings.Split(where, ",")

	whereFinal := make([]libunlynx.WhereQueryAttribute, 0)

	var variable string
	for i := range tmp {
		// if is a variable (w1, w2...)
		if i%2 == 0 {
			variable = tmp[i]
		} else { // if it is a value
			value, err := strconv.Atoi(tmp[i])
			if err != nil {
				return nil, false, nil, "", nil, err
			}

			whereFinal = append(whereFinal, libunlynx.WhereQueryAttribute{Name: variable, Value: *libunlynx.EncryptInt(el.Aggregate, int64(value))})
		}
	}

	if !checkRegex(groupBy, groupByRegex) {
		return nil, false, nil, "", nil, errors.New("error parsing the groupBy parameter(s)")
	}
	groupBy = strings.Replace(groupBy, " ", "", -1)
	groupBy = strings.Replace(groupBy, "{", "", -1)
	groupBy = strings.Replace(groupBy, "}", "", -1)
	groupByFinal := strings.Split(groupBy, ",")

	return sumFinal, count, whereFinal, predicate, groupByFinal, nil
}

// CLIENT END: QUERIER ----------
