package main

import (
	"gopkg.in/urfave/cli.v1"
	"github.com/dedis/onet/log"
	"strconv"
	"github.com/JoaoAndreSa/MedCo/services/skipchain"
	"medblock/service/topology"
	"encoding/hex"
)

// BEGIN CLIENT: SKIPCHAIN ----------
func createTopology(c *cli.Context) error {
	tomlFileName := c.String("file")
	tomlFileSkipName := c.String("fileSkip")
	fileBlock := c.String("block")

	el, err := openGroupToml(tomlFileName)
	if err != nil {
		log.Fatal("Error reading first group toml:", err)
	}
	elSkip, err := openGroupToml(tomlFileSkipName)
	if err != nil {
		log.Fatal("Error reading second group toml:", err)
	}

	log.LLvl1(elSkip)

	client := serviceSkipchain.NewTopologyClient(el.List[0], strconv.Itoa(0))

	st := topology.ReadTopologyToml(fileBlock)
	sb, err := client.SendTopologyCreationQuery(el, st)
	if err != nil {
		log.Fatal("Error creating topology:", err)
	}

	log.LLvl1("ASSDAD",hex.EncodeToString(sb.Hash))

	st = topology.UnmarshalData(sb)
	topology.WriteTopologyToml("block_added.toml",st)

	return nil
}


func addBlockTopology(c *cli.Context) error {
	log.LLvl1("ADD BLOCK TOPOLOGY")
	return nil
}


// CLIENT END: SKIPCHAIN ----------
