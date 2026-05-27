package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/alecthomas/kong"
	"github.com/jvinet/tincan/internal/version"
)

type Globals struct {
	Config string `short:"c" default:"/etc/tincan/config.toml" help:"Path to config file." type:"path"`
}

type App struct {
	Globals `embed:""`

	Init       InitCmd       `cmd:"" help:"Initialize an admin node."`
	Join       JoinCmd       `cmd:"" help:"Initialize a client node config."`
	AddNode    AddNodeCmd    `cmd:"" name:"add-node" help:"Add a node to the directory."`
	RemoveNode RemoveNodeCmd `cmd:"" name:"remove-node" help:"Remove a node from the directory."`
	ListNodes  ListNodesCmd  `cmd:"" name:"list-nodes" help:"List nodes in the directory."`
	Publish    PublishCmd    `cmd:"" help:"Publish the admin working directory."`
	Sync       SyncCmd       `cmd:"" help:"Fetch the latest directory from the dead-drop."`
	Up         UpCmd         `cmd:"" help:"Bring the WireGuard interface up and apply the directory."`
	Down       DownCmd       `cmd:"" help:"Tear down the WireGuard interface."`
	Status     StatusCmd     `cmd:"" help:"Show local Tincan status."`
	Version    VersionCmd    `cmd:"" help:"Print version information."`
}

func Main(args []string) int {
	return run(args, os.Stdout, os.Stderr)
}

func run(args []string, stdout, stderr io.Writer) int {
	var app App
	parser, err := kong.New(&app,
		kong.Name("tincan"),
		kong.Description("Mesh-VPN orchestration for WireGuard."),
		kong.Writers(stdout, stderr),
		kong.BindTo(context.Background(), (*context.Context)(nil)),
		kong.UsageOnError(),
	)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if len(args) == 0 {
		ctx, err := kong.Trace(parser, args)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		if err := ctx.PrintUsage(false); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		return 0
	}
	ctx, err := parser.Parse(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if app.Config != "" && !filepath.IsAbs(app.Config) {
		abs, err := filepath.Abs(app.Config)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		app.Config = abs
	}
	if err := ctx.Run(&app.Globals); err != nil {
		newPrinter(stderr).fail("%s", err)
		return 1
	}
	return 0
}

type VersionCmd struct{}

func (VersionCmd) Run() error {
	p := newPrinter(os.Stdout)
	fmt.Fprintln(os.Stdout, p.style(ansiBold, "tincan "+version.Version))
	p.pairs(
		kv("commit", version.Commit),
		kv("date", version.Date),
	)
	return nil
}
