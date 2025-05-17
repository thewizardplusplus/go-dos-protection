# Change Log

## [v1.1.0](https://github.com/thewizardplusplus/go-dos-protector/tree/v1.1.0) (2025-05-17)

_The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)._

> **Main change**: Added an adapter layer to integrate [PoW](https://en.wikipedia.org/wiki/Proof_of_work)-based [DoS attack](https://en.wikipedia.org/wiki/Denial-of-service_attack) protection with HTTP servers and clients.

### Added

- **Middlewares:**
  - `LoadLevelMiddleware`: tracks the current server load by counting in-flight requests:
    - Intended to be used in conjunction with the dynamic hash difficulty provider.
    - Interacts with the latter via an interface.
  - `ResourceMiddleware`: sets the request URL as the protected resource in the request [context](https://pkg.go.dev/context@go1.23.0#Context):
    - Optionally enriches the URL with a host:
      - Host can be taken from the request itself.
      - Host can be taken from proxy-provided headers.
  - `DoSProtectorMiddleware`: implements the core logic of [DoS attack](https://en.wikipedia.org/wiki/Denial-of-service_attack) protection using the [PoW](https://en.wikipedia.org/wiki/Proof_of_work) algorithm:
    - If a request lacks the solution header `X-Dos-Protector-Solution`, it generates a new challenge, signs it, and returns it via the response headers `X-Dos-Protector-Challenge` and `X-Dos-Protector-Signature`.
    - If a request includes the solution header `X-Dos-Protector-Solution`, it parses and validates the solution:
      - If validation fails, the `403 Forbidden` error response is returned.
      - If validation succeeds, the request proceeds to the protected handler.
    - All operations are delegated to the corresponding use case via an interface.
- **Models:**
  - Introduced adapter-layer models:
    - `Challenge`: corresponds to the domain-level challenge entity.
    - `Solution`: corresponds to the domain-level solution entity.
  - Functions:
    - `NewChallengeFromEntity()` and `NewSolutionFromEntity()`: convert domain entities into adapter-layer models.
    - `ParseChallengeFromQuery()` and `ParseSolutionFromQuery()`: parse adapter-layer models from URL-encoded query strings.
  - Methods:
    - `Challenge.ToQuery()` and `Solution.ToQuery()`: serialize adapter-layer models into URL-encoded query strings.
- **Errors:**
  - `TransformErrorToStatusCode()` maps internal errors to appropriate HTTP status codes:
    - Internal error `dosProtectorUsecaseErrors.ErrInvalidParameters` corresponds to the HTTP status code `400 Bad Request`.
    - Internal error `powErrors.ErrValidationFailure` corresponds to the HTTP status code `403 Forbidden`.
    - Other errors correspond to the HTTP status code `500 Internal Server Error`.
- **Clients:**
  - `HTTPClientWrapper`: a wrapper around the standard [HTTP client](https://pkg.go.dev/net/http@go1.23.0#Client) (via an interface) that automates interaction with `DoSProtectorMiddleware` (see above):
    - Sends an initial `HEAD` request to the target URL to retrieve the challenge and signature from the `X-Dos-Protector-Challenge` and `X-Dos-Protector-Signature` headers, respectively.
    - Parses and solves the challenge by invoking the corresponding use case via an interface.
    - Clones the original request and enriches it with the computed solution and signature in the headers `X-Dos-Protector-Solution` and `X-Dos-Protector-Signature`.
    - Sends the enriched request to the server as usual.
- **Tests:**
  - `newTestHTTPClient()` and `newTestServer()` for reusable test setup.
  - Integration tests for middleware and client interaction with constant and dynamic providers.
- **Docs:**
  - `newExampleHTTPClient()` and `newExampleServer()` for reusable example setup.
  - Demonstrations of usage with constant and dynamic providers.

### Changed

- Refactored `usecases/models`:
  - Renamed `MessageAuthenticationCode` fields to `Signature` for clarity.

## [v1.0.0](https://github.com/thewizardplusplus/go-dos-protector/tree/v1.0.0) (2025-05-10)

The major version.
