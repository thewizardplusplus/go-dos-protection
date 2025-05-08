package dosProtectorAdapterMiddlewares

import (
	"net/http"
	"net/url"

	dosProtectorUsecaseProviders "github.com/thewizardplusplus/go-dos-protector/usecases/providers"
	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

type ResourceMiddleware struct{}

func (middleware ResourceMiddleware) ApplyTo(
	handler http.Handler,
) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		requestURLCopy := &url.URL{}
		*requestURLCopy = *request.URL

		if requestURLCopy.Host == "" {
			requestURLCopy.Host = request.Host
		}

		ctx := dosProtectorUsecaseProviders.WithResource(
			request.Context(),
			powValueTypes.NewResource(requestURLCopy),
		)

		handler.ServeHTTP(writer, request.WithContext(ctx))
	})
}
