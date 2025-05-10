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

## License

The MIT License (MIT)

Copyright &copy; 2025 thewizardplusplus
