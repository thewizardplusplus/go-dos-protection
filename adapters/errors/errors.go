package dosProtectorAdapterErrors

import (
	"errors"
	"net/http"

	dosProtectorUsecaseErrors "github.com/thewizardplusplus/go-dos-protector/usecases/errors"
	powErrors "github.com/thewizardplusplus/go-pow/errors"
)

func TransformErrorToStatusCode(err error) int {
	switch {
	case errors.Is(err, dosProtectorUsecaseErrors.ErrInvalidParameters):
		return http.StatusBadRequest

	case errors.Is(err, powErrors.ErrValidationFailure):
		return http.StatusForbidden

	default:
		return http.StatusInternalServerError
	}
}
