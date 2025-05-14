package dosProtectorAdapterMiddlewares

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	dosProtectorAdapterErrors "github.com/thewizardplusplus/go-dos-protector/adapters/errors"
	dosProtectorAdapterModels "github.com/thewizardplusplus/go-dos-protector/adapters/models"
	dosProtectorUsecaseErrors "github.com/thewizardplusplus/go-dos-protector/usecases/errors"
	dosProtectorUsecaseModels "github.com/thewizardplusplus/go-dos-protector/usecases/models"
	pow "github.com/thewizardplusplus/go-pow"
)

type DoSProtectorUsecase interface {
	GenerateSignedChallenge(
		ctx context.Context,
	) (dosProtectorUsecaseModels.SignedChallenge, error)

	VerifySolutionAndChallengeSignature(
		ctx context.Context,
		params dosProtectorUsecaseModels.VerifySolutionAndChallengeSignatureParams,
	) (pow.Solution, error)
}

type HTTPErrorHandler func(
	writer http.ResponseWriter,
	err string,
	statusCode int,
)

type DoSProtectorMiddlewareOptions struct {
	DoSProtectorUsecase DoSProtectorUsecase
	HTTPErrorHandler    HTTPErrorHandler
}

type DoSProtectorMiddleware struct {
	options DoSProtectorMiddlewareOptions
}

func NewDoSProtectorMiddleware(
	options DoSProtectorMiddlewareOptions,
) DoSProtectorMiddleware {
	return DoSProtectorMiddleware{
		options: options,
	}
}

func (middleware DoSProtectorMiddleware) ApplyTo(
	handler http.Handler,
) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		dosProtectorUsecase := middleware.options.DoSProtectorUsecase
		ctx := request.Context()
		handleErrorf := func(format string, args ...any) {
			err := fmt.Errorf(format, args...)
			statusCode := dosProtectorAdapterErrors.TransformErrorToStatusCode(err)
			middleware.options.HTTPErrorHandler(writer, err.Error(), statusCode)
		}

		solutionHeader :=
			request.Header.Get(dosProtectorAdapterModels.SolutionHeaderKey)
		if solutionHeader == "" {
			signedChallenge, err := dosProtectorUsecase.GenerateSignedChallenge(ctx)
			if err != nil {
				handleErrorf("unable to generate a new signed challenge: %w", err)
				return
			}

			challengeModel, err :=
				dosProtectorAdapterModels.NewChallengeFromEntity(signedChallenge.Challenge)
			if err != nil {
				handleErrorf("unable to construct the challenge model: %w", err)
				return
			}

			writer.Header().Set(
				dosProtectorAdapterModels.ChallengeHeaderKey,
				challengeModel.ToQuery(),
			)
			writer.Header().Set(
				dosProtectorAdapterModels.SignatureHeaderKey,
				signedChallenge.Signature,
			)
			writer.WriteHeader(http.StatusForbidden)

			return
		}

		solutionModel, err :=
			dosProtectorAdapterModels.ParseSolutionFromQuery(solutionHeader)
		if err != nil {
			handleErrorf(
				"unable to parse the solution model: %w",
				errors.Join(err, dosProtectorUsecaseErrors.ErrInvalidParameters),
			)

			return
		}

		signatureHeader :=
			request.Header.Get(dosProtectorAdapterModels.SignatureHeaderKey)
		if signatureHeader == "" {
			handleErrorf(
				"`%s` header is required: %w",
				dosProtectorAdapterModels.SignatureHeaderKey,
				dosProtectorUsecaseErrors.ErrInvalidParameters,
			)

			return
		}

		if _, err := dosProtectorUsecase.VerifySolutionAndChallengeSignature(
			ctx,
			dosProtectorUsecaseModels.VerifySolutionAndChallengeSignatureParams{
				VerifySolutionParams: dosProtectorUsecaseModels.VerifySolutionParams{
					LeadingZeroBitCount: solutionModel.LeadingZeroBitCount,
					CreatedAt:           solutionModel.CreatedAt,
					TTL:                 solutionModel.TTL,
					Resource:            solutionModel.Resource,
					Payload:             solutionModel.Payload,
					HashName:            solutionModel.HashName,
					HashDataLayout:      solutionModel.HashDataLayout,
					Nonce:               solutionModel.Nonce,
					HashSum:             solutionModel.HashSum,
				},

				Signature: signatureHeader,
			},
		); err != nil {
			handleErrorf(
				"unable to verify the solution and challenge signature: %w",
				err,
			)

			return
		}

		handler.ServeHTTP(writer, request)
	})
}
