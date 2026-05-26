package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alecthomas/kong"
	tincanlog "github.com/jvinet/tincan/internal/log"
	"github.com/jvinet/tincan/internal/version"
)

type Globals struct {
	Config string `short:"c" default:"/etc/tincan/config.toml" help:"Path to config file." type:"path"`
	JSON   bool   `name:"json-logs" help:"Emit logs as JSON."`
}

type App struct {
	Globals `embed:""`

	Init       InitCmd       `cmd:"" help:"Initialize an admin node."`
	Join       JoinCmd       `cmd:"" help:"Initialize a client node config."`
	AddNode    AddNodeCmd    `cmd:"" name:"add-node" help:"Add a node to the directory."`
	RemoveNode RemoveNodeCmd `cmd:"" name:"remove-node" help:"Remove a node from the directory."`
	ListNodes  ListNodesCmd  `cmd:"" name:"list-nodes" help:"List nodes in the directory."`
	Publish    PublishCmd    `cmd:"" help:"Publish the admin working directory."`
	Sync       SyncCmd       `cmd:"" help:"Sync WireGuard state from the directory."`
	Status     StatusCmd     `cmd:"" help:"Show local Tincan status."`
	Version    VersionCmd    `cmd:"" help:"Print version information."`
}

func Main(args []string) int {
	var app App
	parser, err := kong.New(&app,
		kong.Name("tincan"),
		kong.Description("Mesh-VPN orchestration for WireGuard."),
		kong.UsageOnError(),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	ctx, err := parser.Parse(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if app.Config != "" && !filepath.IsAbs(app.Config) {
		abs, err := filepath.Abs(app.Config)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		app.Config = abs
	}
	logger := tincanlog.Setup(app.JSON)
	if err := ctx.Run(context.Background(), &app.Globals); err != nil {
		logger.Error(err.Error())
		return 1
	}
	return 0
}

type VersionCmd struct{}

func (VersionCmd) Run() error {
	fmt.Printf("tincan %s\ncommit: %s\ndate: %s\n", version.Version, version.Commit, version.Date)
	return nil
}
