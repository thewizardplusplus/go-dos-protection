package dosProtectorTests

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"time"

	"github.com/AlekSi/pointer"
	"github.com/samber/mo"
	dosProtectorAdapterClients "github.com/thewizardplusplus/go-dos-protector/adapters/clients"
	dosProtectorAdapterMiddlewares "github.com/thewizardplusplus/go-dos-protector/adapters/middlewares"
	dosProtectorUsecases "github.com/thewizardplusplus/go-dos-protector/usecases"
	dosProtectorUsecaseProviders "github.com/thewizardplusplus/go-dos-protector/usecases/providers"
	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

func newTestHashProvider() dosProtectorUsecases.HashProvider {
	hashProvider := dosProtectorUsecaseProviders.NewMapHashProvider()
	hashProvider.RegisterHash("SHA-256", sha256.New)
	hashProvider.RegisterHash("SHA-512", sha512.New)

	return hashProvider
}

type newTestHTTPClientParams struct {
	httpClientAddressStorage *atomic.Pointer[string]
	hashProvider             dosProtectorUsecases.HashProvider
	initialNonceRandomReader io.Reader
}

func newTestHTTPClient(
	params newTestHTTPClientParams,
) dosProtectorAdapterClients.HTTPClientWrapper {
	return dosProtectorAdapterClients.NewHTTPClientWrapper(
		dosProtectorAdapterClients.HTTPClientWrapperOptions{
			HTTPClient: &http.Client{
				Transport: &http.Transport{
					DialContext: func(
						ctx context.Context,
						network string,
						address string,
					) (net.Conn, error) {
						connection, err := (&net.Dialer{}).DialContext(ctx, network, address)
						if err == nil {
							params.httpClientAddressStorage.Store(
								pointer.To(connection.LocalAddr().String()),
							)
						}

						return connection, err
					},
				},
			},
			DoSProtectorUsecase: dosProtectorUsecases.NewClientDoSProtectorUsecase(
				dosProtectorUsecases.ClientDoSProtectorUsecaseOptions{
					HashProvider: params.hashProvider,
				},
			),
			MaxAttemptCount: mo.Some(1000),
			RandomInitialNonceParams: mo.Some(powValueTypes.RandomNonceParams{
				RandomReader: params.initialNonceRandomReader,
				MinRawValue:  big.NewInt(1023),
				MaxRawValue:  big.NewInt(1042),
			}),
		},
	)
}

type middleware func(handler http.Handler) http.Handler

type newTestServerParams struct {
	leadingZeroBitCountProvider   dosProtectorUsecases.LeadingZeroBitCountProvider
	resourceProvider              dosProtectorUsecases.ResourceProvider
	mainSerializedPayloadProvider dosProtectorUsecases.SerializedPayloadProvider
	randomPayloadByteReader       io.Reader
	hashProvider                  dosProtectorUsecases.HashProvider
	gotRequestChannel             chan *http.Request
	handler                       http.Handler
	middlewares                   []middleware
}

func newTestServer(params newTestServerParams) (*httptest.Server, error) {
	ttl, err := powValueTypes.NewTTL(100 * 365 * 24 * time.Hour)
	if err != nil {
		return nil, fmt.Errorf("unable to construct the TTL: %w", err)
	}

	dosProtectorMiddleware :=
		dosProtectorAdapterMiddlewares.NewDoSProtectorMiddleware(
			dosProtectorAdapterMiddlewares.DoSProtectorMiddlewareOptions{
				DoSProtectorUsecase: dosProtectorUsecases.NewServerDoSProtectorUsecase(
					dosProtectorUsecases.ServerDoSProtectorUsecaseOptions{
						LeadingZeroBitCountProvider:   params.leadingZeroBitCountProvider,
						CreatedAtModulus:              ttl.ToDuration(),
						TTL:                           ttl,
						ResourceProvider:              params.resourceProvider,
						MainSerializedPayloadProvider: params.mainSerializedPayloadProvider,
						RandomPayloadByteReader:       params.randomPayloadByteReader,
						RandomPayloadByteCount:        5,
						HashProvider:                  params.hashProvider,
						GenerationHashName:            "SHA-256",
						SecretKey:                     "secret-key",
						SigningHashName:               "SHA-512",
					},
				),
				HTTPErrorHandler: http.Error,
			},
		)

	requestRegisterMiddleware := func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			params.gotRequestChannel <- request.WithContext(context.Background())

			handler.ServeHTTP(writer, request)
		})
	}

	middlewares := make([]middleware, 0, len(params.middlewares)+2)
	middlewares = append(middlewares, dosProtectorMiddleware.ApplyTo)
	middlewares = append(middlewares, params.middlewares...)
	middlewares = append(middlewares, requestRegisterMiddleware)

	handler := params.handler
	for _, middleware := range middlewares {
		handler = middleware(handler)
	}

	return httptest.NewServer(handler), nil
}
