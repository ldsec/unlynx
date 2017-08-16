package main

import (
	"os"

	"gopkg.in/dedis/onet.v1/app"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/urfave/cli.v1"
)

const (
	// BinaryName is the name of the binary
	BinaryName = "i2b2"

	// Version of the binary
	Version = "1.00"

	// DefaultGroupFile is the name of the default file to lookup for group
	// definition
	DefaultGroupFile = "public.toml"

	optionConfig      = "config"
	optionConfigShort = "c"

	optionGroupFile      = "file"
	optionGroupFileShort = "f"

	optionEntryPointIdx = "entryPointIdx"

	optionDecryptKey      = "key"
	optionDecryptKeyShort = "k"
)

/*
Return system error codes signification
0: success
1: failed to init client
2: error in the XML query parsing or during query
*/
func main() {
	cliApp := cli.NewApp()
	cliApp.Name = "i2b2"
	cliApp.Usage = "Query medical information securely and privately"
	cliApp.Version = Version

	binaryFlags := []cli.Flag{
		cli.IntFlag{
			Name:  "debug, d",
			Value: 0,
			Usage: "debug-level: 1 for terse, 5 for maximal",
		},
	}

	encryptFlags := []cli.Flag{
		cli.StringFlag{
			Name:  optionGroupFile + ", " + optionGroupFileShort,
			Value: DefaultGroupFile,
			Usage: "Unlynx group definition file",
		},
	}

	decryptFlags := []cli.Flag{
		cli.StringFlag{
			Name:  optionDecryptKey + ", " + optionDecryptKeyShort,
			Usage: "Base64-encoded key to decrypt a value",
		},
	}

	querierFlags := []cli.Flag{
		cli.StringFlag{
			Name:  optionGroupFile + ", " + optionGroupFileShort,
			Value: DefaultGroupFile,
			Usage: "Unlynx group definition file",
		},
		cli.IntFlag{
			Name:  optionEntryPointIdx,
			Usage: "Index (relative to the group definition file) of the collective authority server to send the query.",
		},
	}

	serverFlags := []cli.Flag{
		cli.StringFlag{
			Name:  optionConfig + ", " + optionConfigShort,
			Value: app.GetDefaultConfigFile(BinaryName),
			Usage: "Configuration file of the server",
		},
	}
	cliApp.Commands = []cli.Command{
		// BEGIN CLIENT: DATA ENCRYPTION ----------
		{
			Name:    "encrypt",
			Aliases: []string{"e"},
			Usage:   "Encrypt an integer with the public key of the collective authority",
			Action:  encryptIntFromApp,
			Flags:   encryptFlags,
		},
		// CLIENT END: DATA ENCRYPTION ------------

		// BEGIN CLIENT: DATA DECRYPTION ----------
		{
			Name:    "decrypt",
			Aliases: []string{"d"},
			Usage:   "Decrypt an integer with the provided private key",
			Action:  decryptIntFromApp,
			Flags:   decryptFlags,
		},
		// CLIENT END: DATA DECRYPTION ------------

		// BEGIN CLIENT: KEY GENERATION ----------
		{
			Name:    "keygen",
			Aliases: []string{"k"},
			Usage:   "Generate a pair of public/private keys.",
			Action:  keyGenerationFromApp,
		},
		// CLIENT END: KEY GENERATION ------------

		// BEGIN CLIENT: QUERIER ----------
		{
			Name:    "runDDT",
			Aliases: []string{"r"},
			Usage:   "Execute the DDT of the query parameters using Unlynx.\nFeed the query parameters XML (UTF-8 encoded) to stdin and close it.",
			Action:  unlynxQueryFromApp,
			Flags:   querierFlags,
		},
		// CLIENT END: QUERIER ----------

		// BEGIN SERVER --------
		{
			Name:  "server",
			Usage: "Start medco server",
			Action: func(c *cli.Context) error {
				runServer(c)
				return nil
			},
			Flags: serverFlags,
			Subcommands: []cli.Command{
				{
					Name:    "setup",
					Aliases: []string{"s"},
					Usage:   "Setup server configuration (interactive)",
					Action: func(c *cli.Context) error {
						if c.String(optionConfig) != "" {
							log.Fatal("[-] Configuration file option cannot be used for the 'setup' command")
						}
						if c.GlobalIsSet("debug") {
							log.Fatal("[-] Debug option cannot be used for the 'setup' command")
						}
						app.InteractiveConfig(BinaryName)
						return nil
					},
				},
			},
		},
		// SERVER END ----------
	}

	cliApp.Flags = binaryFlags
	cliApp.Before = func(c *cli.Context) error {
		log.SetDebugVisible(c.GlobalInt("debug"))
		return nil
	}
	err := cliApp.Run(os.Args)
	log.ErrFatal(err)
}
