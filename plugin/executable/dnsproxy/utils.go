package forward_dnsproxy

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/osutil"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var LogLevels = map[zapcore.Level]slog.Level{
	zap.DebugLevel: slog.LevelDebug,
	zap.InfoLevel:  slog.LevelInfo,
	zap.WarnLevel:  slog.LevelWarn,
	zap.ErrorLevel: slog.LevelError,
}

// initBootstrap initializes the [upstream.Resolver] for bootstrapping upstream
// servers.  It returns the default resolver if no bootstraps were specified.
// The returned resolver will also use system hosts files first.
func initBootstrap(bootstraps []string, opts *upstream.Options) (r upstream.Resolver, err error) {
	var resolvers []upstream.Resolver

	for i, b := range bootstraps {
		var ur *upstream.UpstreamResolver
		ur, err = upstream.NewUpstreamResolver(b, opts)
		if err != nil {
			return nil, fmt.Errorf("creating bootstrap resolver at index %d: %w", i, err)
		}

		resolvers = append(resolvers, upstream.NewCachingResolver(ur))
	}

	switch len(resolvers) {
	case 0:
		etcHosts, hostsErr := upstream.NewDefaultHostsResolver(osutil.RootDirFS(), opts.Logger)
		if hostsErr != nil {
			return net.DefaultResolver, nil
		}

		return upstream.ConsequentResolver{etcHosts, net.DefaultResolver}, nil
	case 1:
		return resolvers[0], nil
	default:
		return upstream.ParallelResolver(resolvers), nil
	}
}
