package appunlynx

import (
	"gopkg.in/urfave/cli.v1"

	// Empty imports to have the init-functions called which should
	// register the protocol
	"github.com/dedis/onet/app"
	// both these blank space imports are necessary to make the app work (onet requirement)
	_ "github.com/lca1/unlynx/protocols"
	_ "github.com/lca1/unlynx/services/default"
)

func runServer(ctx *cli.Context) error {
	// first check the options
	config := ctx.String("config")
	app.RunServer(config)
	return nil
}
