package dosProtectorAdapterClients

import (
	"context"
	"fmt"
	"net/http"

	"github.com/samber/mo"
	dosProtectorAdapterModels "github.com/thewizardplusplus/go-dos-protector/adapters/models"
	dosProtectorUsecaseModels "github.com/thewizardplusplus/go-dos-protector/usecases/models"
	pow "github.com/thewizardplusplus/go-pow"
	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

const (
	ExpectedResponseStatusToHEADRequest = http.StatusForbidden
)

type HTTPClient interface {
	Do(request *http.Request) (*http.Response, error)
}

type DoSProtectorUsecase interface {
	SolveChallenge(
		ctx context.Context,
		params dosProtectorUsecaseModels.SolveChallengeParams,
	) (pow.Solution, error)
}

type HTTPClientWrapperOptions struct {
	HTTPClient               HTTPClient
	DoSProtectorUsecase      DoSProtectorUsecase
	MaxAttemptCount          mo.Option[int]
	RandomInitialNonceParams mo.Option[powValueTypes.RandomNonceParams]
}

type HTTPClientWrapper struct {
	options HTTPClientWrapperOptions
}

func NewHTTPClientWrapper(options HTTPClientWrapperOptions) HTTPClientWrapper {
	return HTTPClientWrapper{
		options: options,
	}
}

func (wrapper HTTPClientWrapper) Do(
	request *http.Request,
) (*http.Response, error) {
	ctx := request.Context()

	signedChallengeModel, err :=
		wrapper.requestChallenge(ctx, request.URL.String())
	if err != nil {
		return nil, fmt.Errorf("unable to request a new challenge: %w", err)
	}

	solution, err := wrapper.options.DoSProtectorUsecase.SolveChallenge(
		ctx,
		dosProtectorUsecaseModels.SolveChallengeParams{
			LeadingZeroBitCount:      signedChallengeModel.LeadingZeroBitCount,
			CreatedAt:                signedChallengeModel.CreatedAt,
			TTL:                      signedChallengeModel.TTL,
			Resource:                 signedChallengeModel.Resource,
			Payload:                  signedChallengeModel.Payload,
			HashName:                 signedChallengeModel.HashName,
			HashDataLayout:           signedChallengeModel.HashDataLayout,
			MaxAttemptCount:          wrapper.options.MaxAttemptCount,
			RandomInitialNonceParams: wrapper.options.RandomInitialNonceParams,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("unable to solve the challenge: %w", err)
	}

	solutionModel, err := dosProtectorAdapterModels.NewSolutionFromEntity(solution)
	if err != nil {
		return nil, fmt.Errorf("unable to construct the solution model: %w", err)
	}

	copiedRequest := request.Clone(ctx)
	copiedRequest.Header.Set(
		dosProtectorAdapterModels.SolutionHeaderKey,
		solutionModel.ToQuery(),
	)
	copiedRequest.Header.Set(
		dosProtectorAdapterModels.SignatureHeaderKey,
		signedChallengeModel.Signature,
	)

	response, err := wrapper.options.HTTPClient.Do(copiedRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to send the main request: %w", err)
	}

	return response, nil
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
