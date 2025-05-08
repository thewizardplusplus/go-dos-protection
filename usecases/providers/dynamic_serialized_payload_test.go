package dosProtectorUsecaseProviders

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	dosProtectorUsecases "github.com/thewizardplusplus/go-dos-protector/usecases"
	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

func TestWithSerializedPayload(test *testing.T) {
	type args struct {
		ctx               context.Context
		serializedPayload powValueTypes.SerializedPayload
	}

	for _, data := range []struct {
		name string
		args args
		want context.Context
	}{
		{
			name: "success",
			args: args{
				ctx:               context.Background(),
				serializedPayload: powValueTypes.NewSerializedPayload("dummy"),
			},
			want: context.WithValue(
				context.Background(),
				serializedPayloadCtxKey{},
				powValueTypes.NewSerializedPayload("dummy"),
			),
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			got := WithSerializedPayload(data.args.ctx, data.args.serializedPayload)

			assert.Equal(test, data.want, got)
		})
	}
}

func TestDynamicSerializedPayload_interface(test *testing.T) {
	assert.Implements(
		test,
		(*dosProtectorUsecases.SerializedPayloadProvider)(nil),
		DynamicSerializedPayload{},
	)
}

func TestDynamicSerializedPayload_ProvideSerializedPayload(test *testing.T) {
	type args struct {
		ctx context.Context
	}

	for _, data := range []struct {
		name    string
		args    args
		want    powValueTypes.SerializedPayload
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "success",
			args: args{
				ctx: context.WithValue(
					context.Background(),
					serializedPayloadCtxKey{},
					powValueTypes.NewSerializedPayload("dummy"),
				),
			},
			want:    powValueTypes.NewSerializedPayload("dummy"),
			wantErr: assert.NoError,
		},
		{
			name: "error/there isn't a serialized payload in the context",
			args: args{
				ctx: context.Background(),
			},
			want:    powValueTypes.SerializedPayload{},
			wantErr: assert.Error,
		},
		{
			name: "error/serialized payload has an invalid type",
			args: args{
				ctx: context.WithValue(
					context.Background(),
					serializedPayloadCtxKey{},
					"invalid",
				),
			},
			want:    powValueTypes.SerializedPayload{},
			wantErr: assert.Error,
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			got, err :=
				(DynamicSerializedPayload{}).ProvideSerializedPayload(data.args.ctx)

			assert.Equal(test, data.want, got)
			data.wantErr(test, err)
		})
	}
}
