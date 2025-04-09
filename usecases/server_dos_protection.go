package dosProtectionUsecases

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	pow "github.com/thewizardplusplus/go-pow"
	powErrors "github.com/thewizardplusplus/go-pow/errors"
	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

type LeadingZeroBitCountProvider interface {
	ProvideLeadingZeroBitCount(
		ctx context.Context,
	) (powValueTypes.LeadingZeroBitCount, error)
}

type ResourceProvider interface {
	ProvideResource(ctx context.Context) (powValueTypes.Resource, error)
}

type ServerDoSProtectionUsecaseOptions struct {
	LeadingZeroBitCountProvider LeadingZeroBitCountProvider
	CreatedAtModulus            time.Duration
	TTL                         powValueTypes.TTL
	ResourceProvider            ResourceProvider
	PayloadReader               io.Reader
	PayloadSize                 int
	HashProvider                HashProvider
	GenerationHashName          string
}

type ServerDoSProtectionUsecase struct {
	options ServerDoSProtectionUsecaseOptions
}

func NewServerDoSProtectionUsecase(
	options ServerDoSProtectionUsecaseOptions,
) ServerDoSProtectionUsecase {
	return ServerDoSProtectionUsecase{
		options: options,
	}
}

func (usecase ServerDoSProtectionUsecase) GenerateChallenge(
	ctx context.Context,
) (pow.Challenge, error) {
	leadingZeroBitCount, err :=
		usecase.options.LeadingZeroBitCountProvider.ProvideLeadingZeroBitCount(ctx)
	if err != nil {
		return pow.Challenge{}, fmt.Errorf(
			"unable to get the leading zero bit count: %w",
			err,
		)
	}

	rawCreatedAt := time.Now().Truncate(usecase.options.CreatedAtModulus)
	createdAt, err := powValueTypes.NewCreatedAt(rawCreatedAt)
	if err != nil {
		return pow.Challenge{}, fmt.Errorf(
			"unable to construct the `CreatedAt` timestamp: %w",
			err,
		)
	}

	resource, err := usecase.options.ResourceProvider.ProvideResource(ctx)
	if err != nil {
		return pow.Challenge{}, fmt.Errorf("unable to get the resource: %w", err)
	}

	rawPayload := make([]byte, usecase.options.PayloadSize)
	if _, err := io.ReadFull(
		usecase.options.PayloadReader,
		rawPayload,
	); err != nil {
		return pow.Challenge{}, fmt.Errorf(
			"unable to read the payload bytes: %w",
			errors.Join(err, powErrors.ErrIO),
		)
	}

	hash, err := usecase.options.HashProvider.ProvideHashByName(
		ctx,
		usecase.options.GenerationHashName,
	)
	if err != nil {
		return pow.Challenge{}, fmt.Errorf(
			"unable to get the hash by name %s: %w",
			usecase.options.GenerationHashName,
			err,
		)
	}

	challenge, err := pow.NewChallengeBuilder().
		SetLeadingZeroBitCount(leadingZeroBitCount).
		SetCreatedAt(createdAt).
		SetTTL(usecase.options.TTL).
		SetResource(resource).
		SetSerializedPayload(
			powValueTypes.NewSerializedPayload(hex.EncodeToString(rawPayload)),
		).
		SetHash(hash).
		SetHashDataLayout(powValueTypes.MustParseHashDataLayout(
			"{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
				"{{ .Challenge.CreatedAt.MustGet.ToString }}" +
				"{{ .Challenge.TTL.MustGet.ToString }}" +
				"{{ .Challenge.Resource.MustGet.ToString }}" +
				"{{ .Challenge.SerializedPayload.ToString }}" +
				"{{ .Challenge.Hash.Name }}" +
				"{{ .Challenge.HashDataLayout.ToString }}" +
				"{{ .Nonce.ToString }}",
		)).
		Build()
	if err != nil {
		return pow.Challenge{}, fmt.Errorf("unable to build the challenge: %w", err)
	}

	return challenge, nil
}
