package dosProtectorAdapterClients

import (
	"context"
	"fmt"
	"net/http"

	dosProtectorAdapterModels "github.com/thewizardplusplus/go-dos-protector/adapters/models"
)

const (
	ExpectedResponseStatusToHEADRequest = http.StatusForbidden
)

type HTTPClient interface {
	Do(request *http.Request) (*http.Response, error)
}

type HTTPClientWrapperOptions struct {
	HTTPClient HTTPClient
}

type HTTPClientWrapper struct {
	options HTTPClientWrapperOptions
}

func NewHTTPClientWrapper(options HTTPClientWrapperOptions) HTTPClientWrapper {
	return HTTPClientWrapper{
		options: options,
	}
}

func (wrapper HTTPClientWrapper) requestChallenge(
	ctx context.Context,
	url string,
) (dosProtectorAdapterModels.SignedChallenge, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return dosProtectorAdapterModels.SignedChallenge{}, fmt.Errorf(
			"unable to construct a new HEAD request: %w",
			err,
		)
	}

	response, err := wrapper.options.HTTPClient.Do(request)
	if err != nil {
		return dosProtectorAdapterModels.SignedChallenge{}, fmt.Errorf(
			"unable to send the HEAD request: %w",
			err,
		)
	}
	if response.StatusCode != ExpectedResponseStatusToHEADRequest {
		return dosProtectorAdapterModels.SignedChallenge{}, fmt.Errorf(
			"unexpected status of the response to the HEAD request: %d (should be %d)",
			response.StatusCode,
			ExpectedResponseStatusToHEADRequest,
		)
	}

	challengeHeader :=
		response.Header.Get(dosProtectorAdapterModels.ChallengeHeaderKey)
	if challengeHeader == "" {
		return dosProtectorAdapterModels.SignedChallenge{}, fmt.Errorf(
			"`%s` header is required",
			dosProtectorAdapterModels.ChallengeHeaderKey,
		)
	}

	challengeModel, err :=
		dosProtectorAdapterModels.ParseChallengeFromQuery(challengeHeader)
	if err != nil {
		return dosProtectorAdapterModels.SignedChallenge{}, fmt.Errorf(
			"unable to parse the challenge model: %w",
			err,
		)
	}

	signatureHeader :=
		response.Header.Get(dosProtectorAdapterModels.SignatureHeaderKey)
	if signatureHeader == "" {
		return dosProtectorAdapterModels.SignedChallenge{}, fmt.Errorf(
			"`%s` header is required",
			dosProtectorAdapterModels.SignatureHeaderKey,
		)
	}

	signedChallengeModel := dosProtectorAdapterModels.SignedChallenge{
		Challenge: challengeModel,
		Signature: signatureHeader,
	}
	return signedChallengeModel, nil
}
