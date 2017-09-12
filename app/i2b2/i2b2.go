package main

import (
	"os"

	"gopkg.in/dedis/onet.v1/app"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/urfave/cli.v1"
)

const (
	// BinaryName is the name of the binary
	BinaryName = "unlynxI2B2"

	// Version of the binary
	Version = "1.00"

	// DefaultGroupFile is the name of the default file to lookup for group definition
	DefaultGroupFile = "public.toml"
	// DefaultClinicalFile is the name of the default clinical file (dataset)
	DefaultClinicalFile = ""
	// DefaultGenomicFile is the name of the default genomic file (dataset)
	DefaultGenomicFile = ""
	// DefaultSizeFile is the size of the data that we are going to consider (1 - original)
	DefaultSizeFile = 1

	// DefaultDBhost is the name of the default database hostname
	DefaultDBhost = "localhost"
	// DefaultDBport is the value of the default database access port
	DefaultDBport = 5434
	// DefaultDBname is the name of the default database name
	DefaultDBname = "medcodeployment"
	// DefaultDBuser is the name of the default user
	DefaultDBuser = "postgres"
	// DefaultDBpassword is the name of the default password
	DefaultDBpassword = "prigen2017"

	optionConfig      = "config"
	optionConfigShort = "c"

	optionGroupFile      = "file"
	optionGroupFileShort = "f"

	optionEntryPointIdx = "entryPointIdx"

	optionProofs = "proofs"

	optionDecryptKey      = "key"
	optionDecryptKeyShort = "k"

	optionSizeFile      = "replay"
	optionSizeFileShort = "r"

	optionClinicalFile      = "clinical"
	optionClinicalFileShort = "cl"

	optionGenomicFile      = "genomic"
	optionGenomicFileShort = "g"

	optionListSensitive      = "sensitive"
	optionListSensitiveShort = "s"

	// database settings
	optionDBhost      = "host"
	optionDBhostShort = "h"

	optionDBport      = "port"
	optionDBportShort = "p"

	optionDBname      = "n"
	optionDBnameShort = "name"

	optionDBuser      = "user"
	optionDBuserShort = "u"

	optionDBpassword      = "password"
	optionDBpasswordShort = "d"
)

/*
Return system error codes signification
0: success
1: failed to init client
2: error in the XML query parsing or during query
*/
func main() {
	cliApp := cli.NewApp()
	cliApp.Name = "unlynxI2B2"
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

	loaderFlags := []cli.Flag{
		cli.StringFlag{
			Name:  optionGroupFile + ", " + optionGroupFileShort,
			Value: DefaultGroupFile,
			Usage: "Unlynx group definition file",
		},
		cli.IntFlag{
			Name:  optionEntryPointIdx,
			Usage: "Index (relative to the group definition file) of the collective authority server to load the data.",
		},
		cli.StringFlag{
			Name:  optionClinicalFile + ", " + optionClinicalFileShort,
			Value: DefaultClinicalFile,
			Usage: "Clinical file to load",
		},
		cli.StringFlag{
			Name:  optionGenomicFile + ", " + optionGenomicFileShort,
			Value: DefaultGenomicFile,
			Usage: "Genomic file to load",
		},
		cli.StringSliceFlag{
			Name:  optionListSensitive + ", " + optionListSensitiveShort,
			Value: &cli.StringSlice{},
			Usage: "Fields listed as sensitive (\"all\" means all clinical fields are considered sensitive)",
		},
		cli.IntFlag{
			Name:  optionSizeFile + ", " + optionSizeFileShort,
			Value: DefaultSizeFile,
			Usage: "Replay dataset (default: 1 - original, 2 - two times more entries, etc.)",
		},
		cli.StringFlag{
			Name:  optionDBhost + ", " + optionDBhostShort,
			Value: DefaultDBhost,
			Usage: "Database hostname",
		},
		cli.IntFlag{
			Name:  optionDBport + ", " + optionDBportShort,
			Value: DefaultDBport,
			Usage: "Database port",
		},
		cli.StringFlag{
			Name:  optionDBname + ", " + optionDBnameShort,
			Value: DefaultDBname,
			Usage: "Database name",
		},
		cli.StringFlag{
			Name:  optionDBuser + ", " + optionDBuserShort,
			Value: DefaultDBuser,
			Usage: "Database user",
		},
		cli.StringFlag{
			Name:  optionDBpassword + ", " + optionDBpasswordShort,
			Value: DefaultDBpassword,
			Usage: "Database password",
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
		cli.IntFlag{
			Name:  optionProofs,
			Value: 0,
			Usage: "Enable/Disable proofs",
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

		// BEGIN CLIENT: DATA LOADER ----------
		{
			Name:    "loader",
			Aliases: []string{"l"},
			Usage:   "Load data from clinical and genomic files.",
			Action:  loadData,
			Flags:   loaderFlags,
		},
		// CLIENT END: DATA LOADER ------------

		// BEGIN CLIENT: QUERIER ----------
		{
			Name:    "run",
			Aliases: []string{"r"},
			Usage:   "Execute a DDT or Aggregation request using Unlynx. Feed the query XML (UTF-8 encoded) to stdin and close it.",
			Action:  unlynxRequestFromApp,
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
