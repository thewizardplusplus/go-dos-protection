package dosProtectorUsecases

import (
	"context"
	"errors"
	"fmt"

	dosProtectorUsecaseErrors "github.com/thewizardplusplus/go-dos-protector/usecases/errors"
	dosProtectorUsecaseModels "github.com/thewizardplusplus/go-dos-protector/usecases/models"
	pow "github.com/thewizardplusplus/go-pow"
	powErrors "github.com/thewizardplusplus/go-pow/errors"
	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

type ClientDoSProtectorUsecaseOptions struct {
	HashProvider HashProvider
}

type ClientDoSProtectorUsecase struct {
	options ClientDoSProtectorUsecaseOptions
}

func NewClientDoSProtectorUsecase(
	options ClientDoSProtectorUsecaseOptions,
) ClientDoSProtectorUsecase {
	return ClientDoSProtectorUsecase{
		options: options,
	}
}

func (usecase ClientDoSProtectorUsecase) SolveChallenge(
	ctx context.Context,
	params dosProtectorUsecaseModels.SolveChallengeParams,
) (pow.Solution, error) {
	leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(
		params.LeadingZeroBitCount,
	)
	if err != nil {
		return pow.Solution{}, fmt.Errorf(
			"unable to construct the leading zero bit count: %w",
			errors.Join(err, dosProtectorUsecaseErrors.ErrInvalidParameters),
		)
	}

	createdAt, err := powValueTypes.ParseCreatedAt(params.CreatedAt)
	if err != nil {
		return pow.Solution{}, fmt.Errorf(
			"unable to parse the `CreatedAt` timestamp: %w",
			errors.Join(err, dosProtectorUsecaseErrors.ErrInvalidParameters),
		)
	}

	ttl, err := powValueTypes.ParseTTL(params.TTL)
	if err != nil {
		return pow.Solution{}, fmt.Errorf(
			"unable to parse the TTL: %w",
			errors.Join(err, dosProtectorUsecaseErrors.ErrInvalidParameters),
		)
	}

	resource, err := powValueTypes.ParseResource(params.Resource)
	if err != nil {
		return pow.Solution{}, fmt.Errorf(
			"unable to parse the resource: %w",
			errors.Join(err, dosProtectorUsecaseErrors.ErrInvalidParameters),
		)
	}

	hash, err := usecase.options.HashProvider.ProvideHashByName(
		ctx,
		params.HashName,
	)
	if err != nil {
		return pow.Solution{}, fmt.Errorf(
			"unable to get the hash by name %s: %w",
			params.HashName,
			err,
		)
	}

	hashDataLayout, err := powValueTypes.ParseHashDataLayout(params.HashDataLayout)
	if err != nil {
		return pow.Solution{}, fmt.Errorf(
			"unable to parse the hash data layout: %w",
			errors.Join(err, dosProtectorUsecaseErrors.ErrInvalidParameters),
		)
	}

	challenge, err := pow.NewChallengeBuilder().
		SetLeadingZeroBitCount(leadingZeroBitCount).
		SetCreatedAt(createdAt).
		SetTTL(ttl).
		SetResource(resource).
		SetSerializedPayload(
			powValueTypes.NewSerializedPayload(params.Payload),
		).
		SetHash(hash).
		SetHashDataLayout(hashDataLayout).
		Build()
	if err != nil {
		return pow.Solution{}, fmt.Errorf(
			"unable to build the challenge: %w",
			errors.Join(err, dosProtectorUsecaseErrors.ErrInvalidParameters),
		)
	}
	if !challenge.IsAlive() {
		return pow.Solution{}, errors.Join(
			errors.New("challenge is outdated"),
			powErrors.ErrValidationFailure,
		)
	}

	solution, err := challenge.Solve(ctx, pow.SolveParams{
		MaxAttemptCount:          params.MaxAttemptCount,
		RandomInitialNonceParams: params.RandomInitialNonceParams,
	})
	if err != nil {
		if !errors.Is(err, powErrors.ErrIO) &&
			!errors.Is(err, powErrors.ErrTaskInterruption) {
			err = errors.Join(err, dosProtectorUsecaseErrors.ErrInvalidParameters)
		}

		return pow.Solution{}, fmt.Errorf("unable to solve the challenge: %w", err)
	}

	return solution, nil
}
