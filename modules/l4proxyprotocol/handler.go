// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package l4proxyprotocol

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	proxyprotocol "github.com/pires/go-proxyproto"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is a connection handler that accepts the PROXY protocol.
type Handler struct {
	// How long to wait for the PROXY protocol header to be received.
	// Defaults to zero, which means timeout is disabled.
	Timeout caddy.Duration `json:"timeout,omitempty"`

	// An optional list of CIDR ranges to allow/require PROXY headers from.
	Allow  []string `json:"allow,omitempty"`
	allow  []netip.Prefix
	policy proxyprotocol.PolicyFunc
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.proxy_protocol",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the module.
func (h *Handler) Provision(ctx caddy.Context) error {
	if len(h.Allow) != 0 {
		for _, cidr := range h.Allow {
			ipnet, err := netip.ParsePrefix(cidr)
			if err != nil {
				return err
			}
			h.allow = append(h.allow, ipnet)
		}
		h.policy = func(upstream net.Addr) (proxyprotocol.Policy, error) {
			if network := upstream.Network(); caddy.IsUnixNetwork(network) {
				return proxyprotocol.REQUIRE, nil
			}

			host, _, err := net.SplitHostPort(upstream.String())
			if err != nil {
				return proxyprotocol.REJECT, err
			}

			ip, err := netip.ParseAddr(host)
			for _, ipnet := range h.allow {
				if ipnet.Contains(ip) {
					return proxyprotocol.REQUIRE, nil
				}
			}
			return proxyprotocol.REJECT, nil
		}
	}

	h.logger = ctx.Logger(h)
	return nil
}

// newConn creates a new connection which will handle the PROXY protocol. It
// will return nil if the remote IP does not match the allowable CIDR ranges.
//
// This is basically a copy of `Listener.Accept` from the proxyprotocol package.
func (h *Handler) newConn(cx *layer4.Connection) *proxyprotocol.Conn {
	var err error

	proxyHeaderPolicy := proxyprotocol.REQUIRE
	if h.policy != nil {
		proxyHeaderPolicy, err = h.policy(cx.RemoteAddr())
		if err != nil {
			// can't decide the policy, we can't accept the connection
			cx.Close()
			return nil
		}
	}

	if h.Timeout == 0 {
		return proxyprotocol.NewConn(cx, proxyprotocol.WithPolicy(proxyHeaderPolicy))
	}

	return proxyprotocol.NewConn(cx, proxyprotocol.WithPolicy(proxyHeaderPolicy), func(c *proxyprotocol.Conn) {
		c.SetReadDeadline(time.Now().Add(time.Duration(h.Timeout)))
	})
}

// Handle handles the connections.
func (h *Handler) Handle(cx *layer4.Connection, next layer4.Handler) error {
	conn := h.newConn(cx)
	if conn == nil {
		h.logger.Debug("untrusted party not allowed",
			zap.String("remote", cx.RemoteAddr().String()),
			zap.Strings("allow", h.Allow),
		)
		return next.Handle(cx)
	}

	if _, err := conn.Read(make([]byte, 0)); err != nil {
		return fmt.Errorf("parsing the PROXY header: %v", err)
	}
	h.logger.Debug("received the PROXY header",
		zap.String("remote", conn.RemoteAddr().String()),
		zap.String("local", conn.LocalAddr().String()),
	)

	// Set conn as a custom variable on cx.
	cx.SetVar("l4.proxy_protocol.conn", conn)

	return next.Handle(cx.Wrap(conn))
}

// GetConn gets the connection which holds the information received from the PROXY protocol.
func GetConn(cx *layer4.Connection) net.Conn {
	if val := cx.GetVar("l4.proxy_protocol.conn"); val != nil {
		return val.(net.Conn)
	}
	return cx.Conn
}

// Interface guards
var (
	_ caddy.Provisioner  = (*Handler)(nil)
	_ layer4.NextHandler = (*Handler)(nil)
)
