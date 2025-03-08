/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package forward_dnsproxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	slogzap "github.com/samber/slog-zap/v2"
	"go.uber.org/zap"
)

const PluginType = "dnsproxy"

const (
	queryTimeout = time.Second * 5
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
	sequence.MustRegExecQuickSetup(PluginType, QuickSetup)
}

var _ sequence.Executable = (*DNSProxy)(nil)

type DNSProxy struct {
	upstreams []upstream.Upstream
}

type Args struct {
	// options for dnsproxy upstream
	Upstreams          []UpstreamConfig `yaml:"upstreams"`
	InsecureSkipVerify bool             `yaml:"insecure_skip_verify"`
	Bootstrap          []string         `yaml:"bootstrap"`
	Timeout            time.Duration    `yaml:"timeout"`
}

type UpstreamConfig struct {
	Tag  string `yaml:"tag"`
	Addr string `yaml:"addr"`
}

func Init(bp *coremain.BP, args any) (any, error) {
	return NewForward(args.(*Args), bp.L())
}

func QuickSetup(bq sequence.BQ, s string) (any, error) {
	args := &Args{
		Upstreams: []UpstreamConfig{
			{Addr: s},
		},
	}
	return NewForward(args, bq.L())
}

// NewForward returns a Forward with given args.
// args must contain at least one upstream.
func NewForward(args *Args, logger *zap.Logger) (*DNSProxy, error) {
	if len(args.Upstreams) == 0 {
		return nil, errors.New("no upstream is configured")
	}

	if args.Timeout <= 0 {
		args.Timeout = queryTimeout
	}

	logLevel := LogLevels[logger.Level()]

	l := slog.New(slogzap.Option{Level: logLevel, Logger: logger}.NewZapHandler())

	d := new(DNSProxy)
	for i, conf := range args.Upstreams {
		opts := &upstream.Options{
			Logger:             l.With("tag", conf.Tag),
			Timeout:            args.Timeout,
			InsecureSkipVerify: args.InsecureSkipVerify,
		}

		bootstrap, err := initBootstrap(args.Bootstrap, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to init bootstrap: %w", err)
		}

		opts.Bootstrap = bootstrap

		u, err := upstream.AddressToUpstream(conf.Addr, opts)
		if err != nil {
			_ = d.Close()
			return nil, fmt.Errorf("failed to init upsteam #%d: %w", i, err)
		}
		d.upstreams = append(d.upstreams, u)
	}
	return d, nil
}

func (d *DNSProxy) Exec(ctx context.Context, qCtx *query_context.Context) error {
	r, _, err := d.Exchange(ctx, qCtx.Q())
	if err != nil {
		return err
	}
	if r != nil {
		qCtx.SetResponse(r)
	}
	return nil
}

func (d *DNSProxy) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, upstream.Upstream, error) {
	type res struct {
		r   *dns.Msg
		u   upstream.Upstream
		err error
	}
	// Remainder: Always makes a copy of q. dnsproxy/upstream may keep or even modify the q in their
	// Exchange() calls.
	qc := q.Copy()
	c := make(chan res, 1)
	go func() {
		r, u, err := upstream.ExchangeParallel(d.upstreams, qc)
		c <- res{
			r:   r,
			u:   u,
			err: err,
		}
	}()

	select {
	case res := <-c:
		return res.r, res.u, res.err
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}

func (d *DNSProxy) Close() error {
	for _, u := range d.upstreams {
		_ = u.Close()
	}
	return nil
}
