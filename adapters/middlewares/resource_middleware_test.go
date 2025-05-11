package dosProtectorAdapterMiddlewares

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	dosProtectorAdapterMiddlewaresMocks "github.com/thewizardplusplus/go-dos-protector/mocks/github.com/thewizardplusplus/go-dos-protector/adapters/middlewares"
	dosProtectorUsecaseProviders "github.com/thewizardplusplus/go-dos-protector/usecases/providers"
	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

func TestNewResourceMiddleware(test *testing.T) {
	type args struct {
		options ResourceMiddlewareOptions
	}

	for _, data := range []struct {
		name string
		args args
		want ResourceMiddleware
	}{
		{
			name: "success",
			args: args{
				options: ResourceMiddlewareOptions{
					HostMode: AddHostFromProxyHeaders,
				},
			},
			want: ResourceMiddleware{
				options: ResourceMiddlewareOptions{
					HostMode: AddHostFromProxyHeaders,
				},
			},
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			got := NewResourceMiddleware(data.args.options)

			assert.Equal(test, data.want, got)
		})
	}
}

func TestResourceMiddleware_ApplyTo(test *testing.T) {
	type fields struct {
		options ResourceMiddlewareOptions
	}
	type args struct {
		handler func(test *testing.T, request *http.Request) http.Handler
	}
	type handlerArgs struct {
		writer  http.ResponseWriter
		request *http.Request
	}

	for _, data := range []struct {
		name        string
		fields      fields
		args        args
		handlerArgs handlerArgs
	}{
		{
			name: "success/HostMode: UseURLAsIs",
			fields: fields{
				options: ResourceMiddlewareOptions{
					HostMode: UseURLAsIs,
				},
			},
			args: args{
				handler: func(test *testing.T, request *http.Request) http.Handler {
					handlerMock := dosProtectorAdapterMiddlewaresMocks.NewMockhttpHandler(test)
					handlerMock.EXPECT().
						ServeHTTP(
							httptest.NewRecorder(),
							request.WithContext(dosProtectorUsecaseProviders.WithResource(
								request.Context(),
								powValueTypes.NewResource(&url.URL{
									Scheme:   "http",
									Host:     "example-one.com",
									Path:     "/path/to/resource",
									RawQuery: "key=value",
								}),
							)),
						)

					return handlerMock
				},
			},
			handlerArgs: handlerArgs{
				writer: httptest.NewRecorder(),
				request: func() *http.Request {
					request := httptest.NewRequest(
						http.MethodGet,
						"http://example-one.com/path/to/resource?key=value",
						nil,
					)
					request.Host = "example-two.com"
					request.Header.Set("X-Forwarded-Proto", "https")
					request.Header.Set("X-Forwarded-Host", "example-three.com")

					return request
				}(),
			},
		},
		{
			name: "success/HostMode: AddHostFromRequest/Scheme: http",
			fields: fields{
				options: ResourceMiddlewareOptions{
					HostMode: AddHostFromRequest,
				},
			},
			args: args{
				handler: func(test *testing.T, request *http.Request) http.Handler {
					handlerMock := dosProtectorAdapterMiddlewaresMocks.NewMockhttpHandler(test)
					handlerMock.EXPECT().
						ServeHTTP(
							httptest.NewRecorder(),
							request.WithContext(dosProtectorUsecaseProviders.WithResource(
								request.Context(),
								powValueTypes.NewResource(&url.URL{
									Scheme:   "http",
									Host:     "example-two.com",
									Path:     "/path/to/resource",
									RawQuery: "key=value",
								}),
							)),
						)

					return handlerMock
				},
			},
			handlerArgs: handlerArgs{
				writer: httptest.NewRecorder(),
				request: func() *http.Request {
					request := httptest.NewRequest(
						http.MethodGet,
						"http://example-one.com/path/to/resource?key=value",
						nil,
					)
					request.Host = "example-two.com"
					request.Header.Set("X-Forwarded-Proto", "https")
					request.Header.Set("X-Forwarded-Host", "example-three.com")

					return request
				}(),
			},
		},
		{
			name: "success/HostMode: AddHostFromRequest/Scheme: https",
			fields: fields{
				options: ResourceMiddlewareOptions{
					HostMode: AddHostFromRequest,
				},
			},
			args: args{
				handler: func(test *testing.T, request *http.Request) http.Handler {
					handlerMock := dosProtectorAdapterMiddlewaresMocks.NewMockhttpHandler(test)
					handlerMock.EXPECT().
						ServeHTTP(
							httptest.NewRecorder(),
							request.WithContext(dosProtectorUsecaseProviders.WithResource(
								request.Context(),
								powValueTypes.NewResource(&url.URL{
									Scheme:   "https",
									Host:     "example-two.com",
									Path:     "/path/to/resource",
									RawQuery: "key=value",
								}),
							)),
						)

					return handlerMock
				},
			},
			handlerArgs: handlerArgs{
				writer: httptest.NewRecorder(),
				request: func() *http.Request {
					request := httptest.NewRequest(
						http.MethodGet,
						"https://example-one.com/path/to/resource?key=value",
						nil,
					)
					request.Host = "example-two.com"
					request.Header.Set("X-Forwarded-Proto", "http")
					request.Header.Set("X-Forwarded-Host", "example-three.com")

					return request
				}(),
			},
		},
		{
			name: "success/HostMode: AddHostFromProxyHeaders/with the proxy headers",
			fields: fields{
				options: ResourceMiddlewareOptions{
					HostMode: AddHostFromProxyHeaders,
				},
			},
			args: args{
				handler: func(test *testing.T, request *http.Request) http.Handler {
					handlerMock := dosProtectorAdapterMiddlewaresMocks.NewMockhttpHandler(test)
					handlerMock.EXPECT().
						ServeHTTP(
							httptest.NewRecorder(),
							request.WithContext(dosProtectorUsecaseProviders.WithResource(
								request.Context(),
								powValueTypes.NewResource(&url.URL{
									Scheme:   "https",
									Host:     "example-three.com",
									Path:     "/path/to/resource",
									RawQuery: "key=value",
								}),
							)),
						)

					return handlerMock
				},
			},
			handlerArgs: handlerArgs{
				writer: httptest.NewRecorder(),
				request: func() *http.Request {
					request := httptest.NewRequest(
						http.MethodGet,
						"http://example-one.com/path/to/resource?key=value",
						nil,
					)
					request.Host = "example-two.com"
					request.Header.Set("X-Forwarded-Proto", "https")
					request.Header.Set("X-Forwarded-Host", "example-three.com")

					return request
				}(),
			},
		},
		{
			name: "success" +
				"/HostMode: AddHostFromProxyHeaders" +
				"/without the proxy headers" +
				"/Scheme: http",
			fields: fields{
				options: ResourceMiddlewareOptions{
					HostMode: AddHostFromProxyHeaders,
				},
			},
			args: args{
				handler: func(test *testing.T, request *http.Request) http.Handler {
					handlerMock := dosProtectorAdapterMiddlewaresMocks.NewMockhttpHandler(test)
					handlerMock.EXPECT().
						ServeHTTP(
							httptest.NewRecorder(),
							request.WithContext(dosProtectorUsecaseProviders.WithResource(
								request.Context(),
								powValueTypes.NewResource(&url.URL{
									Scheme:   "http",
									Host:     "example-two.com",
									Path:     "/path/to/resource",
									RawQuery: "key=value",
								}),
							)),
						)

					return handlerMock
				},
			},
			handlerArgs: handlerArgs{
				writer: httptest.NewRecorder(),
				request: func() *http.Request {
					request := httptest.NewRequest(
						http.MethodGet,
						"http://example-one.com/path/to/resource?key=value",
						nil,
					)
					request.Host = "example-two.com"

					return request
				}(),
			},
		},
		{
			name: "success" +
				"/HostMode: AddHostFromProxyHeaders" +
				"/without the proxy headers" +
				"/Scheme: https",
			fields: fields{
				options: ResourceMiddlewareOptions{
					HostMode: AddHostFromProxyHeaders,
				},
			},
			args: args{
				handler: func(test *testing.T, request *http.Request) http.Handler {
					handlerMock := dosProtectorAdapterMiddlewaresMocks.NewMockhttpHandler(test)
					handlerMock.EXPECT().
						ServeHTTP(
							httptest.NewRecorder(),
							request.WithContext(dosProtectorUsecaseProviders.WithResource(
								request.Context(),
								powValueTypes.NewResource(&url.URL{
									Scheme:   "https",
									Host:     "example-two.com",
									Path:     "/path/to/resource",
									RawQuery: "key=value",
								}),
							)),
						)

					return handlerMock
				},
			},
			handlerArgs: handlerArgs{
				writer: httptest.NewRecorder(),
				request: func() *http.Request {
					request := httptest.NewRequest(
						http.MethodGet,
						"https://example-one.com/path/to/resource?key=value",
						nil,
					)
					request.Host = "example-two.com"

					return request
				}(),
			},
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			middleware := ResourceMiddleware{
				options: data.fields.options,
			}
			gotHandler :=
				middleware.ApplyTo(data.args.handler(test, data.handlerArgs.request))
			gotHandler.ServeHTTP(data.handlerArgs.writer, data.handlerArgs.request)
		})
	}
}
