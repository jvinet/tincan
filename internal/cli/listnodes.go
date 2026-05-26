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
	fmt.Printf("serial: %d\n", dir.Serial)
	fmt.Printf("network: %s\n", dir.NetworkCIDR)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tIP\tPUBLIC KEY\tENDPOINT")
	for _, node := range dir.Nodes {
		pub := node.PublicKey
		if len(pub) > 12 {
			pub = pub[:12] + "..."
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", node.Name, node.TunnelIP, pub, node.Endpoint)
	}
	return w.Flush()
}
