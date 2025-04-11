package dosProtectionUsecases

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	dosProtectionUsecaseModels "github.com/thewizardplusplus/go-dos-protection/usecases/models"
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
	SecretKey                   string
	SigningHashName             string
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

func (usecase ServerDoSProtectionUsecase) SignChallenge(
	ctx context.Context,
	challenge pow.Challenge,
) (powValueTypes.HashSum, error) {
	signatureDataParts := []string{
		strconv.Itoa(challenge.LeadingZeroBitCount().ToInt()),
		challenge.SerializedPayload().ToString(),
		challenge.Hash().Name(),
		challenge.HashDataLayout().ToString(),
		usecase.options.SecretKey,
	}
	if createdAt, isPresent := challenge.CreatedAt().Get(); isPresent {
		signatureDataParts = append(signatureDataParts, createdAt.ToString())
	}
	if ttl, isPresent := challenge.TTL().Get(); isPresent {
		signatureDataParts = append(signatureDataParts, ttl.ToString())
	}
	if resource, isPresent := challenge.Resource().Get(); isPresent {
		signatureDataParts = append(signatureDataParts, resource.ToString())
	}

	hash, err := usecase.options.HashProvider.ProvideHashByName(
		ctx,
		usecase.options.SigningHashName,
	)
	if err != nil {
		return powValueTypes.HashSum{}, fmt.Errorf(
			"unable to get the hash by name %s: %w",
			usecase.options.SigningHashName,
			err,
		)
	}

	return hash.ApplyTo(strings.Join(signatureDataParts, "")), nil
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

func (usecase ServerDoSProtectionUsecase) GenerateSignedChallenge(
	ctx context.Context,
) (dosProtectionUsecaseModels.SignedChallenge, error) {
	challenge, err := usecase.GenerateChallenge(ctx)
	if err != nil {
		return dosProtectionUsecaseModels.SignedChallenge{}, fmt.Errorf(
			"unable to generate the challenge: %w",
			err,
		)
	}

	signature, err := usecase.SignChallenge(ctx, challenge)
	if err != nil {
		return dosProtectionUsecaseModels.SignedChallenge{}, fmt.Errorf(
			"unable to sign the challenge: %w",
			err,
		)
	}

	signedChallenge := dosProtectionUsecaseModels.SignedChallenge{
		Challenge:                 challenge,
		MessageAuthenticationCode: hex.EncodeToString(signature.ToBytes()),
	}
	return signedChallenge, nil
}

func (usecase ServerDoSProtectionUsecase) VerifySolution(
	ctx context.Context,
	params dosProtectionUsecaseModels.VerifySolutionParams,
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

	expectedResource, err := usecase.options.ResourceProvider.ProvideResource(ctx)
	if err != nil {
		return pow.Solution{}, fmt.Errorf(
			"unable to get the expected resource: %w",
			err,
		)
	}

	resource, err := powValueTypes.ParseResource(params.Resource)
	if err != nil {
		return pow.Solution{}, fmt.Errorf("unable to parse the resource: %w", err)
	}
	if resource.ToString() != expectedResource.ToString() {
		return pow.Solution{}, errors.Join(
			errors.New("resource doesn't match the expected one"),
			powErrors.ErrValidationFailure,
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

	nonce, err := powValueTypes.ParseNonce(params.Nonce)
	if err != nil {
		return pow.Solution{}, fmt.Errorf("unable to parse the nonce: %w", err)
	}

	solutionBuilder := pow.NewSolutionBuilder().
		SetChallenge(challenge).
		SetNonce(nonce)

	if serializedHashSum, isPresent := params.HashSum.Get(); isPresent {
		rawHashSum, err := hex.DecodeString(serializedHashSum)
		if err != nil {
			return pow.Solution{}, fmt.Errorf("unable to parse the hash sum: %w", err)
		}

		solutionBuilder.SetHashSum(powValueTypes.NewHashSum(rawHashSum))
	}

	solution, err := solutionBuilder.Build()
	if err != nil {
		return pow.Solution{}, fmt.Errorf("unable to build the solution: %w", err)
	}

	if err := solution.Verify(); err != nil {
		return pow.Solution{}, fmt.Errorf("unable to verify the solution: %w", err)
	}

	return solution, nil
}

func (usecase ServerDoSProtectionUsecase) VerifySolutionAndChallengeSignature(
	ctx context.Context,
	params dosProtectionUsecaseModels.VerifySolutionAndChallengeSignatureParams,
) (pow.Solution, error) {
	solution, err := usecase.VerifySolution(ctx, params.VerifySolutionParams)
	if err != nil {
		return pow.Solution{}, fmt.Errorf("unable to verify the solution: %w", err)
	}

	expectedSignature, err := usecase.SignChallenge(ctx, solution.Challenge())
	if err != nil {
		return pow.Solution{}, fmt.Errorf("unable to sign the challenge: %w", err)
	}

	signature, err := hex.DecodeString(params.MessageAuthenticationCode)
	if err != nil {
		return pow.Solution{}, fmt.Errorf("unable to parse the signature: %w", err)
	}
	if !bytes.Equal(signature, expectedSignature.ToBytes()) {
		return pow.Solution{}, errors.Join(
			errors.New("signature doesn't match the expected one"),
			powErrors.ErrValidationFailure,
		)
	}

	return solution, nil
}
