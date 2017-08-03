package main

import (
	"gopkg.in/dedis/onet.v1/log"
	"github.com/lca1/unlynx/lib"
	"os"
	"gopkg.in/urfave/cli.v1"
	"io"
	"errors"
)

func keyGenerationFromApp(c *cli.Context) error {

	if c.NArg() != 0 {
		err := errors.New("Wrong number of arguments (none allowed, except for the flags).")
		log.Error(err)
		return cli.NewExitError(err, 3)
	}

	secKey, pubKey := lib.GenKey()
	secKeySer, err1 := lib.SerializeScalar(secKey)
	pubKeySer, err2 := lib.SerializePoint(pubKey)

	if err1 != nil {
		log.Error("Error while serializing.", err1)
		return cli.NewExitError(err1, 4)
	}
	if err2 != nil {
		log.Error("Error while serializing.", err2)
		return cli.NewExitError(err2, 4)
	}

	// output in xml format on stdout
	resultString := "<key_pair><public>" + pubKeySer + "</public><private>" + secKeySer + "</private></key_pair>\n"
	_, err := io.WriteString(os.Stdout, resultString)
	if err != nil {
		log.Error("Error while writing result.", err)
		return cli.NewExitError(err, 4)
	}

	return nil
}

