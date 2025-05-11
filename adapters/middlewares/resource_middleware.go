package dosProtectorAdapterMiddlewares

import (
	"net/http"
	"net/url"

	dosProtectorUsecaseProviders "github.com/thewizardplusplus/go-dos-protector/usecases/providers"
	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

type HostMode int

const (
	UseURLAsIs HostMode = iota
	AddHostFromRequest
	AddHostFromProxyHeaders
)

type ResourceMiddlewareOptions struct {
	HostMode HostMode
}

type ResourceMiddleware struct {
	options ResourceMiddlewareOptions
}

func NewResourceMiddleware(
	options ResourceMiddlewareOptions,
) ResourceMiddleware {
	return ResourceMiddleware{
		options: options,
	}
}

func (middleware ResourceMiddleware) ApplyTo(
	handler http.Handler,
) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		// https://github.com/golang/go/issues/38351
		copiedRequestURL := &url.URL{}
		*copiedRequestURL = *request.URL

		switch middleware.options.HostMode {
		case AddHostFromRequest:
			copiedRequestURL.Scheme = getScheme(request)
			copiedRequestURL.Host = request.Host

		case AddHostFromProxyHeaders:
			scheme := request.Header.Get("X-Forwarded-Proto")
			if scheme == "" {
				scheme = getScheme(request)
			}
			copiedRequestURL.Scheme = scheme

			host := request.Header.Get("X-Forwarded-Host")
			if host == "" {
				host = request.Host
			}
			copiedRequestURL.Host = host
		}

		handler.ServeHTTP(
			writer,
			request.WithContext(dosProtectorUsecaseProviders.WithResource(
				request.Context(),
				powValueTypes.NewResource(copiedRequestURL),
			)),
		)
	})
}

func getScheme(request *http.Request) string {
	if request.TLS != nil {
		return "https"
	}

	return "http"
}
