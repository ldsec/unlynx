package main

import (
	"os"

	"gopkg.in/dedis/onet.v1/app"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/urfave/cli.v1"
)

const (
	// BinaryName is the executable name
	BinaryName = "medco"

	// Version of the binary
	Version = "1.00"

	// DefaultGroupFile is the name of the default file to lookup for group
	// definition
	DefaultGroupFile = "group.toml"

	optionConfig      = "config"
	optionConfigShort = "c"

	optionGroupFile      = "file"
	optionGroupFileShort = "f"

	optionProofs = "proofs"

	// query flags

	optionSum      = "sum"
	optionSumShort = "s"

	optionCount      = "count"
	optionCountShort = "c"

	optionWhere      = "where"
	optionWhereShort = "w"

	optionPredicate      = "predicate"
	optionPredicateShort = "p"

	optionGroupBy      = "groupBy"
	optionGroupByShort = "g"
)

func main() {
	cliApp := cli.NewApp()
	cliApp.Name = "medco"
	cliApp.Usage = "Query medical information securely and privately"
	cliApp.Version = Version

	binaryFlags := []cli.Flag{
		cli.IntFlag{
			Name:  "debug, d",
			Value: 0,
			Usage: "debug-level: 1 for terse, 5 for maximal",
		},
	}

	querierFlags := []cli.Flag{
		cli.StringFlag{
			Name:  optionGroupFile + ", " + optionGroupFileShort,
			Value: DefaultGroupFile,
			Usage: "Medco group definition file",
		},
		cli.BoolFlag{
			Name:  optionProofs,
			Usage: "With proofs",
		},

		// query flags

		cli.StringFlag{
			Name:  optionSum + ", " + optionSumShort,
			Usage: "SELECT s1, s2 -> {s1, s2}",
		},
		cli.BoolFlag{
			Name:  optionCount + ", " + optionCountShort,
			Usage: "Toggle count query",
		},
		cli.StringFlag{
			Name:  optionWhere + ", " + optionWhereShort,
			Usage: "WHERE w1 ... (attributes) -> {w1, 1, w2, 27}",
		},
		cli.StringFlag{
			Name:  optionPredicate + ", " + optionPredicateShort,
			Usage: "WHERE x AND y OR z (predicate) -> (v0 == v1 || v2 == v3) && v4 == v5",
		},
		cli.StringFlag{
			Name:  optionGroupBy + ", " + optionGroupByShort,
			Usage: "GROUP BY g1, g2, g3 -> {g1, g2, g3}",
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
		// BEGIN CLIENT: DATA PROVIDER ----------

		// CLIENT END: DATA PROVIDER ------------

		// BEGIN CLIENT: QUERIER ----------
		{
			Name:    "run",
			Aliases: []string{"r"},
			Usage:   "Run Medco service",
			Action:  runMedco,
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
