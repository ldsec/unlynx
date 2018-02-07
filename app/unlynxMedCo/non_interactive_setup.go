package main

import (
	"errors"
	"gopkg.in/dedis/crypto.v0/config"
	"gopkg.in/dedis/onet.v1/app"
	"gopkg.in/dedis/onet.v1/crypto"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"gopkg.in/urfave/cli.v1"
)

// NonInteractiveSetup setups a cothority node for unlynx in a non-interactive (and without error checks) way
func NonInteractiveSetup(c *cli.Context) error {

	// cli arguments
	serverBindingStr := c.String("serverBinding")
	description := c.String("description")
	privateTomlPath := c.String("privateTomlPath")
	publicTomlPath := c.String("publicTomlPath")

	if serverBindingStr == "" || description == "" || privateTomlPath == "" || publicTomlPath == "" {
		err := errors.New("Arguments not OK")
		log.Error(err)
		return cli.NewExitError(err, 3)
	}

	kp := config.NewKeyPair(network.Suite)
	privStr, _ := crypto.ScalarToStringHex(network.Suite, kp.Secret)
	pubStr, _ := crypto.PointToStringHex(network.Suite, kp.Public)
	public, _ := crypto.StringHexToPoint(network.Suite, pubStr)
	serverBinding := network.NewTCPAddress(serverBindingStr)

	conf := &app.CothorityConfig{
		Public:      pubStr,
		Private:     privStr,
		Address:     serverBinding,
		Description: description,
	}

	server := app.NewServerToml(network.Suite, public, serverBinding, conf.Description)
	group := app.NewGroupToml(server)

	conf.Save(privateTomlPath)
	group.Save(publicTomlPath)

	return nil
}
