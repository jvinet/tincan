package cli

import (
	"context"
	"fmt"
	"os"
)

type ListNodesCmd struct{}

func (c *ListNodesCmd) Run(ctx context.Context, g *Globals) error {
	cfg, err := loadConfig(g)
	if err != nil {
		return err
	}
	d, err := loadReadDrop(cfg)
	if err != nil {
		return err
	}
	dir, err := fetchDirectory(ctx, cfg, d)
	if err != nil {
		return err
	}
	p := newPrinter(os.Stdout)
	p.section("Directory")
	dirPairs := []pair{
		kv("serial", fmt.Sprintf("%d", dir.Serial)),
		kv("network", dir.NetworkCIDR),
		kv("nodes", fmt.Sprintf("%d", len(dir.Nodes))),
	}
	if dir.Domain != "" {
		dirPairs = append(dirPairs, kv("domain", dir.Domain))
	}
	p.pairs(dirPairs...)
	p.blank()
	p.section("Nodes")
	rows := [][]tableCell{{
		p.styledCell(ansiDim, "NAME"),
		p.styledCell(ansiDim, "IP"),
		p.styledCell(ansiDim, "PUBLIC KEY"),
		p.styledCell(ansiDim, "ENDPOINT"),
		p.styledCell(ansiDim, "ROLE"),
	}}
	for _, node := range dir.Nodes {
		pub := node.PublicKey
		if len(pub) > 12 {
			pub = pub[:12] + "..."
		}
		endpoint := node.Endpoint
		if endpoint == "" {
			endpoint = "-"
		}
		role := "-"
		if node.Relay {
			role = "relay"
		}
		rows = append(rows, []tableCell{
			plainCell(node.Name),
			plainCell(node.TunnelIP),
			plainCell(pub),
			plainCell(endpoint),
			plainCell(role),
		})
	}
	p.table("  ", "  ", rows)
	return nil
}
