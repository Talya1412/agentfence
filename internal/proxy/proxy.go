package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"

	"github.com/agentfence/agentfence/internal/audit"
	"github.com/agentfence/agentfence/internal/config"
	"github.com/agentfence/agentfence/internal/protocol"
)

type Proxy struct {
	Config   config.Config
	Audit    io.Writer
	Redactor audit.Redactor
}

func (p Proxy) Run(client io.Reader, clientOut io.Writer, downstream io.ReadWriter) error {
	in, serverIn := bufio.NewReader(client), bufio.NewReader(downstream)
	schemas := map[string]json.RawMessage{}
	for {
		msg, err := protocol.ReadLimit(in, p.frameLimit())
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		kind, err := protocol.Classify(msg)
		if err != nil {
			return err
		}
		switch msg.Method {
		case "tools/list":
			if err := p.list(msg, kind, clientOut, serverIn, downstream, schemas); err != nil {
				return err
			}
		case "tools/call":
			if err := p.call(msg, kind, clientOut, serverIn, downstream, schemas); err != nil {
				return err
			}
		default:
			if err := p.forward(msg, kind, clientOut, serverIn, downstream); err != nil {
				return err
			}
		}
	}
}

func (p Proxy) frameLimit() int {
	if p.Config.Budgets.MaxFrameBytes > 0 {
		return p.Config.Budgets.MaxFrameBytes
	}
	return protocol.DefaultMaxFrameBytes
}

func Inspect(cfg config.Config) string {
	return fmt.Sprintf("mode=%s default=%s tools=%d", cfg.Mode, cfg.Defaults.Decision, len(cfg.Tools))
}
