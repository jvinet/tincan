package cli

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
)

type ListNodesCmd struct{}

func (c *ListNodesCmd) Run(ctx context.Context, g *Globals) error {
	cfg, err := loadConfig(g)
	if err != nil {
		return err
	}
	d, err := loadDrop(cfg)
	if err != nil {
		return err
	}
	dir, err := fetchDirectory(ctx, cfg, d)
	if err != nil {
		return err
	}
	p := newPrinter(os.Stdout)
	p.section("Directory")
	p.pairs(
		kv("serial", fmt.Sprintf("%d", dir.Serial)),
		kv("network", dir.NetworkCIDR),
		kv("nodes", fmt.Sprintf("%d", len(dir.Nodes))),
	)
	p.blank()
	p.section("Nodes")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "  "+p.style(ansiDim, "NAME\tIP\tPUBLIC KEY\tENDPOINT"))
	for _, node := range dir.Nodes {
		pub := node.PublicKey
		if len(pub) > 12 {
			pub = pub[:12] + "..."
		}
		endpoint := node.Endpoint
		if endpoint == "" {
			endpoint = "-"
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", node.Name, node.TunnelIP, pub, endpoint)
	}
	return w.Flush()
}
