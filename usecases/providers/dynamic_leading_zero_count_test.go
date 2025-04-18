package dosProtectorUsecaseProviders

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	dosProtectorUsecases "github.com/thewizardplusplus/go-dos-protector/usecases"
	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

func TestDynamicLeadingZeroBitCount_interface(test *testing.T) {
	assert.Implements(
		test,
		(*dosProtectorUsecases.LeadingZeroBitCountProvider)(nil),
		&DynamicLeadingZeroBitCount{},
	)
}

func TestNewDynamicLeadingZeroBitCount(test *testing.T) {
	type args struct {
		options DynamicLeadingZeroBitCountOptions
	}

	for _, data := range []struct {
		name    string
		args    args
		want    *DynamicLeadingZeroBitCount
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "success",
			args: args{
				options: DynamicLeadingZeroBitCountOptions{
					MinConsideredLoadLevel: 1e3,
					MaxConsideredLoadLevel: 1e4,
					MinRawValue:            23,
					MaxRawValue:            42,
				},
			},
			want: &DynamicLeadingZeroBitCount{
				options: DynamicLeadingZeroBitCountOptions{
					MinConsideredLoadLevel: 1e3,
					MaxConsideredLoadLevel: 1e4,
					MinRawValue:            23,
					MaxRawValue:            42,
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "error/considered load level range cannot be negative",
			args: args{
				options: DynamicLeadingZeroBitCountOptions{
					MinConsideredLoadLevel: 1e4,
					MaxConsideredLoadLevel: 1e3,
					MinRawValue:            23,
					MaxRawValue:            42,
				},
			},
			want:    nil,
			wantErr: assert.Error,
		},
		{
			name: "error/considered load level range cannot be zero",
			args: args{
				options: DynamicLeadingZeroBitCountOptions{
					MinConsideredLoadLevel: 1e3,
					MaxConsideredLoadLevel: 1e3,
					MinRawValue:            23,
					MaxRawValue:            42,
				},
			},
			want:    nil,
			wantErr: assert.Error,
		},
		{
			name: "error/raw value range cannot be negative",
			args: args{
				options: DynamicLeadingZeroBitCountOptions{
					MinConsideredLoadLevel: 1e3,
					MaxConsideredLoadLevel: 1e4,
					MinRawValue:            42,
					MaxRawValue:            23,
				},
			},
			want:    nil,
			wantErr: assert.Error,
		},
		{
			name: "error/raw value range cannot be zero",
			args: args{
				options: DynamicLeadingZeroBitCountOptions{
					MinConsideredLoadLevel: 1e3,
					MaxConsideredLoadLevel: 1e4,
					MinRawValue:            23,
					MaxRawValue:            23,
				},
			},
			want:    nil,
			wantErr: assert.Error,
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			got, err := NewDynamicLeadingZeroBitCount(data.args.options)

			assert.Equal(test, data.want, got)
			data.wantErr(test, err)
		})
	}
}

func TestDynamicLeadingZeroBitCount_IncreaseLoadLevel(test *testing.T) {
	type args struct {
		delta int
	}

	for _, data := range []struct {
		name         string
		provider     *DynamicLeadingZeroBitCount
		args         args
		wantProvider *DynamicLeadingZeroBitCount
	}{
		{
			name: "success",
			provider: func() *DynamicLeadingZeroBitCount {
				provider := &DynamicLeadingZeroBitCount{}
				provider.loadLevel.Store(23)

				return provider
			}(),
			args: args{
				delta: 19,
			},
			wantProvider: func() *DynamicLeadingZeroBitCount {
				provider := &DynamicLeadingZeroBitCount{}
				provider.loadLevel.Store(42)

				return provider
			}(),
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			data.provider.IncreaseLoadLevel(data.args.delta)

			assert.Equal(test, data.wantProvider, data.provider)
		})
	}
}

func TestDynamicLeadingZeroBitCount_DecreaseLoadLevel(test *testing.T) {
	type args struct {
		delta int
	}

	for _, data := range []struct {
		name         string
		provider     *DynamicLeadingZeroBitCount
		args         args
		wantProvider *DynamicLeadingZeroBitCount
	}{
		{
			name: "success",
			provider: func() *DynamicLeadingZeroBitCount {
				provider := &DynamicLeadingZeroBitCount{}
				provider.loadLevel.Store(42)

				return provider
			}(),
			args: args{
				delta: 19,
			},
			wantProvider: func() *DynamicLeadingZeroBitCount {
				provider := &DynamicLeadingZeroBitCount{}
				provider.loadLevel.Store(23)

				return provider
			}(),
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			data.provider.DecreaseLoadLevel(data.args.delta)

			assert.Equal(test, data.wantProvider, data.provider)
		})
	}
}

func TestDynamicLeadingZeroBitCount_ProvideLeadingZeroBitCount(test *testing.T) { //nolint:lll
	type args struct {
		ctx context.Context
	}

	for _, data := range []struct {
		name     string
		provider *DynamicLeadingZeroBitCount
		args     args
		want     powValueTypes.LeadingZeroBitCount
		wantErr  assert.ErrorAssertionFunc
	}{
		{
			name: "success/load level is less than its minimum",
			provider: func() *DynamicLeadingZeroBitCount {
				provider := &DynamicLeadingZeroBitCount{
					options: DynamicLeadingZeroBitCountOptions{
						MinConsideredLoadLevel: 1e3,
						MaxConsideredLoadLevel: 1e4,
						MinRawValue:            23,
						MaxRawValue:            42,
					},
				}
				provider.loadLevel.Store(1e2)

				return provider
			}(),
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
		{
			name: "success/load level is equal to its minimum",
			provider: func() *DynamicLeadingZeroBitCount {
				provider := &DynamicLeadingZeroBitCount{
					options: DynamicLeadingZeroBitCountOptions{
						MinConsideredLoadLevel: 1e3,
						MaxConsideredLoadLevel: 1e4,
						MinRawValue:            23,
						MaxRawValue:            42,
					},
				}
				provider.loadLevel.Store(1e3)

				return provider
			}(),
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
		{
			name: "success/load level is greater than its maximum",
			provider: func() *DynamicLeadingZeroBitCount {
				provider := &DynamicLeadingZeroBitCount{
					options: DynamicLeadingZeroBitCountOptions{
						MinConsideredLoadLevel: 1e3,
						MaxConsideredLoadLevel: 1e4,
						MinRawValue:            23,
						MaxRawValue:            42,
					},
				}
				provider.loadLevel.Store(1e5)

				return provider
			}(),
			args: args{
				ctx: context.Background(),
			},
			want: func() powValueTypes.LeadingZeroBitCount {
				value, err := powValueTypes.NewLeadingZeroBitCount(42)
				require.NoError(test, err)

				return value
			}(),
			wantErr: assert.NoError,
		},
		{
			name: "success/load level is equal to its maximum",
			provider: func() *DynamicLeadingZeroBitCount {
				provider := &DynamicLeadingZeroBitCount{
					options: DynamicLeadingZeroBitCountOptions{
						MinConsideredLoadLevel: 1e3,
						MaxConsideredLoadLevel: 1e4,
						MinRawValue:            23,
						MaxRawValue:            42,
					},
				}
				provider.loadLevel.Store(1e4)

				return provider
			}(),
			args: args{
				ctx: context.Background(),
			},
			want: func() powValueTypes.LeadingZeroBitCount {
				value, err := powValueTypes.NewLeadingZeroBitCount(42)
				require.NoError(test, err)

				return value
			}(),
			wantErr: assert.NoError,
		},
		{
			name: "success/load level is 50% of its range",
			provider: func() *DynamicLeadingZeroBitCount {
				provider := &DynamicLeadingZeroBitCount{
					options: DynamicLeadingZeroBitCountOptions{
						MinConsideredLoadLevel: 1e3,
						MaxConsideredLoadLevel: 1e4,
						MinRawValue:            23,
						MaxRawValue:            42,
					},
				}
				provider.loadLevel.Store(5500)

				return provider
			}(),
			args: args{
				ctx: context.Background(),
			},
			want: func() powValueTypes.LeadingZeroBitCount {
				value, err := powValueTypes.NewLeadingZeroBitCount(33)
				require.NoError(test, err)

				return value
			}(),
			wantErr: assert.NoError,
		},
		{
			name: "success/load level is 33% of its range",
			provider: func() *DynamicLeadingZeroBitCount {
				provider := &DynamicLeadingZeroBitCount{
					options: DynamicLeadingZeroBitCountOptions{
						MinConsideredLoadLevel: 1e3,
						MaxConsideredLoadLevel: 1e4,
						MinRawValue:            23,
						MaxRawValue:            42,
					},
				}
				provider.loadLevel.Store(3630)

				return provider
			}(),
			args: args{
				ctx: context.Background(),
			},
			want: func() powValueTypes.LeadingZeroBitCount {
				value, err := powValueTypes.NewLeadingZeroBitCount(29)
				require.NoError(test, err)

				return value
			}(),
			wantErr: assert.NoError,
		},
		{
			name: "success/load level is 66% of its range",
			provider: func() *DynamicLeadingZeroBitCount {
				provider := &DynamicLeadingZeroBitCount{
					options: DynamicLeadingZeroBitCountOptions{
						MinConsideredLoadLevel: 1e3,
						MaxConsideredLoadLevel: 1e4,
						MinRawValue:            23,
						MaxRawValue:            42,
					},
				}
				provider.loadLevel.Store(7260)

				return provider
			}(),
			args: args{
				ctx: context.Background(),
			},
			want: func() powValueTypes.LeadingZeroBitCount {
				value, err := powValueTypes.NewLeadingZeroBitCount(36)
				require.NoError(test, err)

				return value
			}(),
			wantErr: assert.NoError,
		},
		{
			name: "error",
			provider: func() *DynamicLeadingZeroBitCount {
				provider := &DynamicLeadingZeroBitCount{
					options: DynamicLeadingZeroBitCountOptions{
						MinConsideredLoadLevel: 1e3,
						MaxConsideredLoadLevel: 1e4,
						MinRawValue:            -42,
						MaxRawValue:            -23,
					},
				}
				provider.loadLevel.Store(5500)

				return provider
			}(),
			args: args{
				ctx: context.Background(),
			},
			want:    powValueTypes.LeadingZeroBitCount{},
			wantErr: assert.Error,
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			got, err := data.provider.ProvideLeadingZeroBitCount(data.args.ctx)

			assert.Equal(test, data.want, got)
			data.wantErr(test, err)
		})
	}
}
