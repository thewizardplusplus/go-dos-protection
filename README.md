# go-dos-protector

[![GoDoc](https://godoc.org/github.com/thewizardplusplus/go-dos-protector?status.svg)](https://godoc.org/github.com/thewizardplusplus/go-dos-protector)
[![Go Report Card](https://goreportcard.com/badge/github.com/thewizardplusplus/go-dos-protector)](https://goreportcard.com/report/github.com/thewizardplusplus/go-dos-protector)
[![lint](https://github.com/thewizardplusplus/go-dos-protector/actions/workflows/lint.yaml/badge.svg)](https://github.com/thewizardplusplus/go-dos-protector/actions/workflows/lint.yaml)
[![test](https://github.com/thewizardplusplus/go-dos-protector/actions/workflows/test.yaml/badge.svg)](https://github.com/thewizardplusplus/go-dos-protector/actions/workflows/test.yaml)
[![codecov](https://codecov.io/gh/thewizardplusplus/go-dos-protector/graph/badge.svg?token=81EVNXEM2F)](https://codecov.io/gh/thewizardplusplus/go-dos-protector)

A library implementing [denial-of-service attack (DoS attack)](https://en.wikipedia.org/wiki/Denial-of-service_attack) protection using the [Proof-of-Work (PoW)](https://en.wikipedia.org/wiki/Proof_of_work) algorithm.

## Features

- use of patterns:
  - implementation based on [Clean Architecture](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html) principles:
    - separate use case layers for server and client;
    - adapter layer for integrating with HTTP servers and clients;
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
  - **providers:**
    - extensible provider interfaces for:
      - hash difficulty;
      - target resource [URI](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier);
      - static payload part;
    - built-in provider implementations:
      - constant value providers;
      - dynamic providers:
        - hash difficulty based on current server load (active request count);
        - target resource [URI](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier) and static payload extracted from a [context](https://pkg.go.dev/context@go1.23.0#Context);
- adapter layer:
  - **middlewares:**
    - `LoadLevelMiddleware`: tracks the current server load by counting in-flight requests:
      - intended to be used in conjunction with the dynamic hash difficulty provider (see above);
      - interacts with the latter via an interface;
    - `ResourceMiddleware`: sets the request URL as the protected resource in the request [context](https://pkg.go.dev/context@go1.23.0#Context):
      - optionally enriches the URL with a host:
        - host can be taken from the request itself;
        - host can be taken from proxy-provided headers;
    - `DoSProtectorMiddleware`: implements the core logic of [DoS attack](https://en.wikipedia.org/wiki/Denial-of-service_attack) protection using the [PoW](https://en.wikipedia.org/wiki/Proof_of_work) algorithm:
      - if a request lacks the solution header `X-Dos-Protector-Solution`, it generates a new challenge, signs it, and returns it via the response headers `X-Dos-Protector-Challenge` and `X-Dos-Protector-Signature`;
      - if a request includes the solution header `X-Dos-Protector-Solution`, it parses and validates the solution:
        - if validation fails, the `403 Forbidden` error response is returned;
        - if validation succeeds, the request proceeds to the protected handler;
      - all operations are delegated to the corresponding use case via an interface;
  - **models:**
    - introduced adapter-layer models:
      - `Challenge`: corresponds to the domain-level challenge entity;
      - `Solution`: corresponds to the domain-level solution entity;
    - functions:
      - `NewChallengeFromEntity()` and `NewSolutionFromEntity()`: convert domain entities into adapter-layer models;
      - `ParseChallengeFromQuery()` and `ParseSolutionFromQuery()`: parse adapter-layer models from URL-encoded query strings;
    - methods:
      - `Challenge.ToQuery()` and `Solution.ToQuery()`: serialize adapter-layer models into URL-encoded query strings;
  - **errors:**
    - `TransformErrorToStatusCode()` maps internal errors to appropriate HTTP status codes:
      - internal error `dosProtectorUsecaseErrors.ErrInvalidParameters` corresponds to the HTTP status code `400 Bad Request`;
      - internal error `powErrors.ErrValidationFailure` corresponds to the HTTP status code `403 Forbidden`;
      - other errors correspond to the HTTP status code `500 Internal Server Error`;
  - **clients:**
    - `HTTPClientWrapper`: a wrapper around the standard [HTTP client](https://pkg.go.dev/net/http@go1.23.0#Client) (via an interface) that automates interaction with `DoSProtectorMiddleware` (see above):
      - sends an initial `HEAD` request to the target URL to retrieve the challenge and signature from the `X-Dos-Protector-Challenge` and `X-Dos-Protector-Signature` headers, respectively;
      - parses and solves the challenge by invoking the corresponding use case via an interface;
      - clones the original request and enriches it with the computed solution and signature in the headers `X-Dos-Protector-Solution` and `X-Dos-Protector-Signature`;
      - sends the enriched request to the server as usual.

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
