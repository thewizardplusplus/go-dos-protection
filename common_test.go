package dosProtector

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/samber/mo"
	dosProtectorAdapterClients "github.com/thewizardplusplus/go-dos-protector/adapters/clients"
	dosProtectorAdapterMiddlewares "github.com/thewizardplusplus/go-dos-protector/adapters/middlewares"
	dosProtectorUsecases "github.com/thewizardplusplus/go-dos-protector/usecases"
	dosProtectorUsecaseProviders "github.com/thewizardplusplus/go-dos-protector/usecases/providers"
	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

func newExampleHashProvider() dosProtectorUsecases.HashProvider {
	hashProvider := dosProtectorUsecaseProviders.NewMapHashProvider()
	hashProvider.RegisterHash("SHA-256", sha256.New)
	hashProvider.RegisterHash("SHA-512", sha512.New)

	return hashProvider
}

func newExampleHTTPClient(
	hashProvider dosProtectorUsecases.HashProvider,
) dosProtectorAdapterClients.HTTPClientWrapper {
	return dosProtectorAdapterClients.NewHTTPClientWrapper(
		dosProtectorAdapterClients.HTTPClientWrapperOptions{
			HTTPClient: http.DefaultClient,
			DoSProtectorUsecase: dosProtectorUsecases.NewClientDoSProtectorUsecase(
				dosProtectorUsecases.ClientDoSProtectorUsecaseOptions{
					HashProvider: hashProvider,
				},
			),
			MaxAttemptCount: mo.Some(1000),
			RandomInitialNonceParams: mo.Some(powValueTypes.RandomNonceParams{
				RandomReader: rand.Reader,
				MinRawValue:  big.NewInt(1023),
				MaxRawValue:  big.NewInt(1042),
			}),
		},
	)
}

type middleware func(handler http.Handler) http.Handler

type newExampleServerParams struct {
	leadingZeroBitCountProvider   dosProtectorUsecases.LeadingZeroBitCountProvider
	resourceProvider              dosProtectorUsecases.ResourceProvider
	mainSerializedPayloadProvider dosProtectorUsecases.SerializedPayloadProvider
	hashProvider                  dosProtectorUsecases.HashProvider
	handler                       http.Handler
	middlewares                   []middleware
}

func newExampleServer(params newExampleServerParams) (*httptest.Server, error) {
	ttl, err := powValueTypes.NewTTL(10 * time.Minute)
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
						RandomPayloadByteReader:       rand.Reader,
						RandomPayloadByteCount:        128,
						HashProvider:                  params.hashProvider,
						GenerationHashName:            "SHA-256",
						SecretKey:                     "secret-key",
						SigningHashName:               "SHA-512",
					},
				),
				HTTPErrorHandler: http.Error,
			},
		)

	middlewares := make([]middleware, 0, len(params.middlewares)+1)
	middlewares = append(middlewares, dosProtectorMiddleware.ApplyTo)
	middlewares = append(middlewares, params.middlewares...)

	handler := params.handler
	for _, middleware := range middlewares {
		handler = middleware(handler)
	}

	return httptest.NewServer(handler), nil
}
