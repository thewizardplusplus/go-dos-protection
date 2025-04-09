package dosProtectionUsecases

import (
	"context"
	"errors"
	"fmt"

	dosProtectionUsecaseModels "github.com/thewizardplusplus/go-dos-protection/usecases/models"
	pow "github.com/thewizardplusplus/go-pow"
	powErrors "github.com/thewizardplusplus/go-pow/errors"
	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

type ClientDoSProtectionUsecaseOptions struct {
	HashProvider HashProvider
}

type ClientDoSProtectionUsecase struct {
	options ClientDoSProtectionUsecaseOptions
}

func NewClientDoSProtectionUsecase(
	options ClientDoSProtectionUsecaseOptions,
) ClientDoSProtectionUsecase {
	return ClientDoSProtectionUsecase{
		options: options,
	}
}

func (usecase ClientDoSProtectionUsecase) SolveChallenge(
	ctx context.Context,
	params dosProtectionUsecaseModels.SolveChallengeParams,
) (pow.Solution, error) {
	leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(
		params.LeadingZeroBitCount,
	)
	if err != nil {
		return pow.Solution{}, fmt.Errorf(
			"unable to construct the leading zero bit count: %w",
			err,
		)
	}

	createdAt, err := powValueTypes.ParseCreatedAt(params.CreatedAt)
	if err != nil {
		return pow.Solution{}, fmt.Errorf(
			"unable to parse the `CreatedAt` timestamp: %w",
			err,
		)
	}

	ttl, err := powValueTypes.ParseTTL(params.TTL)
	if err != nil {
		return pow.Solution{}, fmt.Errorf("unable to parse the TTL: %w", err)
	}

	resource, err := powValueTypes.ParseResource(params.Resource)
	if err != nil {
		return pow.Solution{}, fmt.Errorf("unable to parse the resource: %w", err)
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
			err,
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
		return pow.Solution{}, fmt.Errorf("unable to build the challenge: %w", err)
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
		return pow.Solution{}, fmt.Errorf("unable to solve the challenge: %w", err)
	}

	return solution, nil
}
