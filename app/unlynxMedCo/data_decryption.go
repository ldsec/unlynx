package main

import (
	"errors"
	"github.com/lca1/unlynx/lib"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/urfave/cli.v1"
	"io"
	"os"
	"strconv"
)

func decryptIntFromApp(c *cli.Context) error {

	// cli arguments
	secKeySerialized := c.String("key")
	secKey, err := lib.DeserializeScalar(secKeySerialized)
	if err != nil {
		log.Error(err)
		return cli.NewExitError(err, 4)
	}

	if c.NArg() != 1 {
		err := errors.New("Wrong number of arguments (only 1 allowed, except for the flags)")
		log.Error(err)
		return cli.NewExitError(err, 3)
	}

	// value to decrypt
	toDecryptSerialized := c.Args().Get(0)
	toDecrypt := lib.NewCipherTextFromBase64(toDecryptSerialized)

	// decryption
	decVal := lib.DecryptInt(secKey, *toDecrypt)

	// output in xml format on stdout
	resultString := "<decrypted>" + strconv.FormatInt(decVal, 10) + "</decrypted>\n"
	_, err = io.WriteString(os.Stdout, resultString)
	if err != nil {
		log.Error("Error while writing result.", err)
		return cli.NewExitError(err, 4)
	}

	return nil
}
