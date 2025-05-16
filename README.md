# go-dos-protector

[![GoDoc](https://godoc.org/github.com/thewizardplusplus/go-dos-protector?status.svg)](https://godoc.org/github.com/thewizardplusplus/go-dos-protector)
[![Go Report Card](https://goreportcard.com/badge/github.com/thewizardplusplus/go-dos-protector)](https://goreportcard.com/report/github.com/thewizardplusplus/go-dos-protector)
[![lint](https://github.com/thewizardplusplus/go-dos-protector/actions/workflows/lint.yaml/badge.svg)](https://github.com/thewizardplusplus/go-dos-protector/actions/workflows/lint.yaml)
[![test](https://github.com/thewizardplusplus/go-dos-protector/actions/workflows/test.yaml/badge.svg)](https://github.com/thewizardplusplus/go-dos-protector/actions/workflows/test.yaml)
[![codecov](https://codecov.io/gh/thewizardplusplus/go-dos-protector/graph/badge.svg?token=81EVNXEM2F)](https://codecov.io/gh/thewizardplusplus/go-dos-protector)

A library implementing [denial-of-service attack (DoS attack)](https://en.wikipedia.org/wiki/Denial-of-service_attack) protection using the [Proof-of-Work (PoW)](https://en.wikipedia.org/wiki/Proof_of_work) algorithm.

## Features

- use of patterns:
  - implementation based on [Clean Architecture](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html) principles with separate use case layers for server and client;
  - input parsing and validation handled internally in the use cases (inputs are passed as raw DTOs);
  - relies on the library [`github.com/thewizardplusplus/go-pow`](https://github.com/thewizardplusplus/go-pow) for [PoW](https://en.wikipedia.org/wiki/Proof_of_work) algorithm implementation;
- use cases:
  - **server-side:**
    - `SignChallenge()`: generate a [message authentication code (MAC)](https://en.wikipedia.org/wiki/Message_authentication_code) signature for a challenge:
      - [MAC](https://en.wikipedia.org/wiki/Message_authentication_code) signature generation uses a secret key and configurable hashing algorithm;
    - `GenerateChallenge()`: generate a challenge with specified parameters:
      - number of leading zero bits (hash difficulty);
      - current timestamp rounded to a configurable precision;
      - time to live (TTL);
      - target resource [URI](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier);
      - payload consisting of static and random parts;
      - hashing algorithm;
    - `GenerateSignedChallenge()`: generate a challenge and sign it;
    - `VerifySolution()`: verify the correctness of a [PoW](https://en.wikipedia.org/wiki/Proof_of_work) solution;
    - `VerifySolutionAndChallengeSignature()`: verify both [PoW](https://en.wikipedia.org/wiki/Proof_of_work) solution and challenge [MAC](https://en.wikipedia.org/wiki/Message_authentication_code) signature;
  - **client-side:**
    - `SolveChallenge()`: solve a challenge using the [PoW](https://en.wikipedia.org/wiki/Proof_of_work) algorithm;
- providers:
  - extensible provider interfaces for:
    - hash difficulty;
    - target resource [URI](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier);
    - static payload part;
  - built-in provider implementations:
    - constant value providers;
    - dynamic providers:
      - hash difficulty based on current server load (active request count);
      - target resource [URI](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier) and static payload extracted from a [context](https://pkg.go.dev/context@go1.23.0#Context).

## Installation

```
$ go get github.com/thewizardplusplus/go-dos-protector
```

## Examples

With the constant providers:

```go
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"
	"log"
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

func main() {
	hashProvider := newExampleHashProvider()

	leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(5)
	if err != nil {
		log.Fatalf("unable to construct the leading zero bit count: %s", err)
	}

	resource, err := powValueTypes.ParseResource("https://example.com/")
	if err != nil {
		log.Fatalf("unable to construct the resource: %s", err)
	}

	var mux http.ServeMux
	mux.Handle("GET /api/v1/echo", http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		writer.Write([]byte("Hello, World!\n")) //nolint:errcheck
	}))

	leadingZeroBitCountProvider :=
		dosProtectorUsecaseProviders.NewConstantLeadingZeroBitCount(
			leadingZeroBitCount,
		)
	resourceProvider := dosProtectorUsecaseProviders.NewConstantResource(resource)
	mainSerializedPayloadProvider :=
		dosProtectorUsecaseProviders.NewConstantSerializedPayload(
			powValueTypes.NewSerializedPayload("dummy"),
		)
	server, err := newExampleServer(newExampleServerParams{
		leadingZeroBitCountProvider:   leadingZeroBitCountProvider,
		resourceProvider:              resourceProvider,
		mainSerializedPayloadProvider: mainSerializedPayloadProvider,
		hashProvider:                  hashProvider,
		handler:                       &mux,
		middlewares:                   []middleware{},
	})
	if err != nil {
		log.Fatalf("unable to construct the example server: %s", err)
	}
	defer server.Close()

	request, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/echo", nil)
	if err != nil {
		log.Fatalf("unable to construct the request: %s", err)
	}

	httpClient := newExampleHTTPClient(hashProvider)
	response, err := httpClient.Do(request)
	if err != nil {
		log.Fatalf("unable to send the request: %s", err)
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("unable to read the response body: %s", err)
	}

	fmt.Println(response.Status)
	fmt.Print(string(responseBody))

	// Output:
	// 200 OK
	// Hello, World!
}
```

With the dynamic providers:

```go
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"
	"log"
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

func main() {
	hashProvider := newExampleHashProvider()

	leadingZeroBitCountProvider, err :=
		dosProtectorUsecaseProviders.NewDynamicLeadingZeroBitCount(
			dosProtectorUsecaseProviders.DynamicLeadingZeroBitCountOptions{
				MinConsideredLoadLevel: 1e3,
				MaxConsideredLoadLevel: 1e4,
				MinRawValue:            5,
				MaxRawValue:            10,
			},
		)
	if err != nil {
		log.Fatalf("unable to construct the leading zero bit count provider: %s", err)
	}

	var mux http.ServeMux
	mux.Handle("GET /api/v1/echo", http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		writer.Write([]byte("Hello, World!\n")) //nolint:errcheck
	}))

	serializedPayloadMiddleware := func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			handler.ServeHTTP(
				writer,
				request.WithContext(dosProtectorUsecaseProviders.WithSerializedPayload(
					request.Context(),
					powValueTypes.NewSerializedPayload(request.Header.Get("User-Agent")),
				)),
			)
		})
	}
	resourceMiddleware := dosProtectorAdapterMiddlewares.NewResourceMiddleware(
		dosProtectorAdapterMiddlewares.ResourceMiddlewareOptions{
			HostMode: dosProtectorAdapterMiddlewares.AddHostFromRequest,
		},
	)
	loadLevelMiddleware := dosProtectorAdapterMiddlewares.NewLoadLevelMiddleware(
		dosProtectorAdapterMiddlewares.LoadLevelMiddlewareOptions{
			LoadLevelRegister: leadingZeroBitCountProvider,
		},
	)

	var resourceProvider dosProtectorUsecaseProviders.DynamicResource
	var mainSerializedPayloadProvider dosProtectorUsecaseProviders.DynamicSerializedPayload //nolint:lll
	server, err := newExampleServer(newExampleServerParams{
		leadingZeroBitCountProvider:   leadingZeroBitCountProvider,
		resourceProvider:              resourceProvider,
		mainSerializedPayloadProvider: mainSerializedPayloadProvider,
		hashProvider:                  hashProvider,
		handler:                       &mux,
		middlewares: []middleware{
			serializedPayloadMiddleware,
			resourceMiddleware.ApplyTo,
			loadLevelMiddleware.ApplyTo,
		},
	})
	if err != nil {
		log.Fatalf("unable to construct the example server: %s", err)
	}
	defer server.Close()

	request, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/echo", nil)
	if err != nil {
		log.Fatalf("unable to construct the request: %s", err)
	}

	httpClient := newExampleHTTPClient(hashProvider)
	response, err := httpClient.Do(request)
	if err != nil {
		log.Fatalf("unable to send the request: %s", err)
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("unable to read the response body: %s", err)
	}

	fmt.Println(response.Status)
	fmt.Print(string(responseBody))

	// Output:
	// 200 OK
	// Hello, World!
}
```

## License

The MIT License (MIT)

Copyright &copy; 2025 thewizardplusplus
