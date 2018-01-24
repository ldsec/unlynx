package main

import (
	"errors"
	"github.com/lca1/unlynx/app/unlynxMedCo/loader"
	"gopkg.in/dedis/onet.v1/app"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/urfave/cli.v1"
	"os"
	"strconv"
	"time"
)

func computePerfFromApp(c *cli.Context) error {

	// cli arguments
	groupFilePath := c.String(optionGroupFile)
	entryPointIdx := c.Int(optionEntryPointIdx)
	perfType := c.String(optionPerfType)

	// generate el with group file
	f, err := os.Open(groupFilePath)
	if err != nil {
		log.Error("Error while opening group file", err)
		return cli.NewExitError(err, 1)
	}
	el, err := app.ReadGroupToml(f)
	if err != nil {
		log.Error("Error while reading group file", err)
		return cli.NewExitError(err, 1)
	}
	if len(el.List) <= 0 {
		log.Error("Empty or invalid group file", err)
		return cli.NewExitError(err, 1)
	}

	// perform test
	switch perfType {
	case "encryptAndTag":

		// parameter
		if c.NArg() != 1 {
			err := errors.New("1 argument needed (number of elements to test)")
			log.Error(err)
			return cli.NewExitError(err, 3)
		}

		nbElements, err := strconv.ParseInt(c.Args().Get(0), 10, 64)
		if err != nil {
			log.Error(err)
			return cli.NewExitError(err, 2)
		}

		// allocate array and run test
		testValues := make([]int64, 0, nbElements)

		for i := int64(0); i < nbElements; i++ {
			testValues = append(testValues, i)
		}

		start := time.Now()
		loader.EncryptAndTag(testValues, el, entryPointIdx)
		log.LLvl1("Encrypt and tag for ", nbElements, "... (", time.Since(start), ")")

	}

	return nil
}
