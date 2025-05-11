package dosProtectorAdapterMiddlewares

import (
	"net/http"
)

type LoadLevelRegister interface {
	IncreaseLoadLevel(delta int)
	DecreaseLoadLevel(delta int)
}

type LoadLevelMiddlewareOptions struct {
	LoadLevelRegister LoadLevelRegister
}

type LoadLevelMiddleware struct {
	options LoadLevelMiddlewareOptions
}

func NewLoadLevelMiddleware(
	options LoadLevelMiddlewareOptions,
) LoadLevelMiddleware {
	return LoadLevelMiddleware{
		options: options,
	}
}

func (middleware LoadLevelMiddleware) ApplyTo(
	handler http.Handler,
) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		middleware.options.LoadLevelRegister.IncreaseLoadLevel(1)
		defer middleware.options.LoadLevelRegister.DecreaseLoadLevel(1)

		handler.ServeHTTP(writer, request)
	})
}
