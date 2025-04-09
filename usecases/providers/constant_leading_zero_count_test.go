package dosProtectionUsecaseProviders

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	dosProtectionUsecases "github.com/thewizardplusplus/go-dos-protection/usecases"
	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

func TestConstantLeadingZeroBitCount_interface(test *testing.T) {
	assert.Implements(
		test,
		(*dosProtectionUsecases.LeadingZeroBitCountProvider)(nil),
		ConstantLeadingZeroBitCount{},
	)
}

func TestNewConstantLeadingZeroBitCount(test *testing.T) {
	type args struct {
		leadingZeroBitCount powValueTypes.LeadingZeroBitCount
	}

	for _, data := range []struct {
		name string
		args args
		want ConstantLeadingZeroBitCount
	}{
		{
			name: "success",
			args: args{
				leadingZeroBitCount: func() powValueTypes.LeadingZeroBitCount {
					value, err := powValueTypes.NewLeadingZeroBitCount(23)
					require.NoError(test, err)

					return value
				}(),
			},
			want: ConstantLeadingZeroBitCount{
				leadingZeroBitCount: func() powValueTypes.LeadingZeroBitCount {
					value, err := powValueTypes.NewLeadingZeroBitCount(23)
					require.NoError(test, err)

					return value
				}(),
			},
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			got := NewConstantLeadingZeroBitCount(data.args.leadingZeroBitCount)

			assert.Equal(test, data.want, got)
		})
	}
}

func TestConstantLeadingZeroBitCount_ProvideLeadingZeroBitCount(test *testing.T) { //nolint:lll
	type fields struct {
		leadingZeroBitCount powValueTypes.LeadingZeroBitCount
	}
	type args struct {
		ctx context.Context
	}

	for _, data := range []struct {
		name    string
		fields  fields
		args    args
		want    powValueTypes.LeadingZeroBitCount
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "success",
			fields: fields{
				leadingZeroBitCount: func() powValueTypes.LeadingZeroBitCount {
					value, err := powValueTypes.NewLeadingZeroBitCount(23)
					require.NoError(test, err)

					return value
				}(),
			},
			args: args{
				ctx: context.Background(),
			},
			want: func() powValueTypes.LeadingZeroBitCount {
				value, err := powValueTypes.NewLeadingZeroBitCount(23)
				require.NoError(test, err)

				return value
			}(),
			wantErr: assert.NoError,
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			provider := ConstantLeadingZeroBitCount{
				leadingZeroBitCount: data.fields.leadingZeroBitCount,
			}
			got, err := provider.ProvideLeadingZeroBitCount(data.args.ctx)

			assert.Equal(test, data.want, got)
			data.wantErr(test, err)
		})
	}
}
