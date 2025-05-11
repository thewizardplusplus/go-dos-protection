package dosProtectorAdapterErrors

import (
	"fmt"
	"net/http"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	dosProtectorUsecaseErrors "github.com/thewizardplusplus/go-dos-protector/usecases/errors"
	powErrors "github.com/thewizardplusplus/go-pow/errors"
)

func TestTransformErrorToStatusCode(test *testing.T) {
	type args struct {
		err error
	}

	for _, data := range []struct {
		name string
		args args
		want int
	}{
		{
			name: "success/invalid parameters",
			args: args{
				err: fmt.Errorf(
					"error occurred: %w",
					dosProtectorUsecaseErrors.ErrInvalidParameters,
				),
			},
			want: http.StatusBadRequest,
		},
		{
			name: "success/validation failure",
			args: args{
				err: fmt.Errorf("error occurred: %w", powErrors.ErrValidationFailure),
			},
			want: http.StatusForbidden,
		},
		{
			name: "success/regular error",
			args: args{
				err: fmt.Errorf("error occurred: %w", iotest.ErrTimeout),
			},
			want: http.StatusInternalServerError,
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			got := TransformErrorToStatusCode(data.args.err)

			assert.Equal(test, data.want, got)
		})
	}
}
