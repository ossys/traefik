package stripprefixa

import (
	"context"
	"net/http"
	"strings"

	"github.com/containous/traefik/v2/pkg/config/dynamic"
	"github.com/containous/traefik/v2/pkg/log"
	"github.com/containous/traefik/v2/pkg/middlewares"
	"github.com/containous/traefik/v2/pkg/tracing"
	"github.com/opentracing/opentracing-go/ext"
)

const (
	// ForwardedPrefixHeader is the default header to set prefix.
	ForwardedPrefixHeader = "X-Forwarded-Prefix"
	typeName              = "StripPrefixA"
)

// stripPrefix is a middleware used to strip prefix from an URL request.
type stripPrefixA struct {
	next       http.Handler
	prefixes   []string
	forceSlash bool // TODO Must be removed (breaking), the default behavior must be forceSlash=false
	name       string
}

// New creates a new strip prefix middleware.
func New(ctx context.Context, next http.Handler, config dynamic.StripPrefixA, name string) (http.Handler, error) {
	log.FromContext(middlewares.GetLoggerCtx(ctx, name, typeName)).Debug("Creating middleware")
	return &stripPrefixA{
		prefixes:   config.Prefixes,
		forceSlash: config.ForceSlash,
		next:       next,
		name:       name,
	}, nil
}

func (s *stripPrefixA) GetTracingInformation() (string, ext.SpanKindEnum) {
	return s.name, tracing.SpanKindNoneEnum
}

func (s *stripPrefixA) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	for _, prefix := range s.prefixes {
		if strings.HasPrefix(req.URL.Path, prefix) {
			req.URL.Path = s.getPrefixStripped(req.URL.Path, prefix)
			if req.URL.RawPath != "" {
				req.URL.RawPath = s.getPrefixStripped(req.URL.RawPath, prefix)
			}
			s.serveRequest(rw, req, strings.TrimSpace(prefix))
			return
		}
	}
	s.next.ServeHTTP(rw, req)
}

func (s *stripPrefixA) serveRequest(rw http.ResponseWriter, req *http.Request, prefix string) {
	req.Header.Add(ForwardedPrefixHeader, prefix)
	req.RequestURI = req.URL.RequestURI()
	s.next.ServeHTTP(rw, req)
}

func (s *stripPrefixA) getPrefixStripped(urlPath, prefix string) string {
	if s.forceSlash {
		// Only for compatibility reason with the previous behavior,
		// but the previous behavior is wrong.
		// This needs to be removed in the next breaking version.
		return "/" + strings.TrimPrefix(strings.TrimPrefix(urlPath, prefix), "/")
	}

	return ensureLeadingSlash(strings.TrimPrefix(urlPath, prefix))
}

func ensureLeadingSlash(str string) string {
	if str == "" {
		return str
	}

	if str[0] == '/' {
		return str
	}

	return "/" + str
}
