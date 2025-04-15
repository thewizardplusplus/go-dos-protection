package dosProtectorUsecaseProviders

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	dosProtectorUsecases "github.com/thewizardplusplus/go-dos-protector/usecases"
	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

func TestConstantSerializedPayload_interface(test *testing.T) {
	assert.Implements(
		test,
		(*dosProtectorUsecases.SerializedPayloadProvider)(nil),
		ConstantSerializedPayload{},
	)
}

func TestNewConstantSerializedPayload(test *testing.T) {
	type args struct {
		serializedPayload powValueTypes.SerializedPayload
	}

	for _, data := range []struct {
		name string
		args args
		want ConstantSerializedPayload
	}{
		{
			name: "success",
			args: args{
				serializedPayload: powValueTypes.NewSerializedPayload("dummy"),
			},
			want: ConstantSerializedPayload{
				serializedPayload: powValueTypes.NewSerializedPayload("dummy"),
			},
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			got := NewConstantSerializedPayload(data.args.serializedPayload)

			assert.Equal(test, data.want, got)
		})
	}
}

func TestConstantSerializedPayload_ProvideSerializedPayload(test *testing.T) {
	type fields struct {
		serializedPayload powValueTypes.SerializedPayload
	}
	type args struct {
		ctx context.Context
	}

	for _, data := range []struct {
		name    string
		fields  fields
		args    args
		want    powValueTypes.SerializedPayload
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "success",
			fields: fields{
				serializedPayload: powValueTypes.NewSerializedPayload("dummy"),
			},
			args: args{
				ctx: context.Background(),
			},
			want:    powValueTypes.NewSerializedPayload("dummy"),
			wantErr: assert.NoError,
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			provider := ConstantSerializedPayload{
				serializedPayload: data.fields.serializedPayload,
			}
			got, err := provider.ProvideSerializedPayload(data.args.ctx)

			assert.Equal(test, data.want, got)
			data.wantErr(test, err)
		})
	}
}
