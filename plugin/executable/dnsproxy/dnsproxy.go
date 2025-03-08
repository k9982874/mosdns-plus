/*
 * Created At: 2022/09/26
 * Created by Kevin(k9982874.gmail). All rights reserved.
 * Home page: https://github.com/k9982874/mosdns-plus
 * Reference to the project dnsproxy(github.com/AdguardTeam/dnsproxy)
 *
 * Please distribute this file under the GNU General Public License.
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
	InsecureSkipVerify *bool            `yaml:"insecure_skip_verify"`
	Bootstrap          []string         `yaml:"bootstrap"`
	Timeout            *time.Duration   `yaml:"timeout"`
}

type UpstreamConfig struct {
	Tag                string         `yaml:"tag"`
	Addr               string         `yaml:"addr"`
	InsecureSkipVerify *bool          `yaml:"insecure_skip_verify"`
	Bootstrap          []string       `yaml:"bootstrap"`
	Timeout            *time.Duration `yaml:"timeout"`
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

	logLevel := LogLevels[logger.Level()]

	l := slog.New(slogzap.Option{Level: logLevel, Logger: logger}.NewZapHandler())

	d := new(DNSProxy)
	for i, conf := range args.Upstreams {
		insecureSkipVerify := false
		if conf.Timeout != nil {
			insecureSkipVerify = *conf.InsecureSkipVerify
		} else if args.Timeout != nil {
			insecureSkipVerify = *args.InsecureSkipVerify
		}

		timeout := queryTimeout
		if conf.Timeout != nil {
			timeout = *conf.Timeout
		} else if args.Timeout != nil {
			timeout = *args.Timeout
		}

		var bootstrapList []string
		if conf.Bootstrap != nil {
			bootstrapList = append(bootstrapList, conf.Bootstrap...)
		} else if args.Bootstrap != nil {
			bootstrapList = append(bootstrapList, args.Bootstrap...)
		}

		opts := &upstream.Options{
			Logger:             l.With("tag", conf.Tag),
			Timeout:            timeout,
			InsecureSkipVerify: insecureSkipVerify,
		}

		bootstrap, err := initBootstrap(bootstrapList, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to init bootstrap #%d: %w", i, err)
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
