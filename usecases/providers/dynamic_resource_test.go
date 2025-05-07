package dosProtectorUsecaseProviders

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	dosProtectorUsecases "github.com/thewizardplusplus/go-dos-protector/usecases"
	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

func TestWithResource(test *testing.T) {
	type args struct {
		ctx      context.Context
		resource powValueTypes.Resource
	}

	for _, data := range []struct {
		name string
		args args
		want context.Context
	}{
		{
			name: "success",
			args: args{
				ctx: context.Background(),
				resource: powValueTypes.NewResource(&url.URL{
					Scheme: "https",
					Host:   "example.com",
					Path:   "/",
				}),
			},
			want: context.WithValue(
				context.Background(),
				resourceCtxKey{},
				powValueTypes.NewResource(&url.URL{
					Scheme: "https",
					Host:   "example.com",
					Path:   "/",
				}),
			),
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			got := WithResource(data.args.ctx, data.args.resource)

			assert.Equal(test, data.want, got)
		})
	}
}

func TestDynamicResource_interface(test *testing.T) {
	assert.Implements(
		test,
		(*dosProtectorUsecases.ResourceProvider)(nil),
		DynamicResource{},
	)
}

func TestDynamicResource_ProvideResource(test *testing.T) {
	type args struct {
		ctx context.Context
	}

	for _, data := range []struct {
		name    string
		args    args
		want    powValueTypes.Resource
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "success",
			args: args{
				ctx: context.WithValue(
					context.Background(),
					resourceCtxKey{},
					powValueTypes.NewResource(&url.URL{
						Scheme: "https",
						Host:   "example.com",
						Path:   "/",
					}),
				),
			},
			want: powValueTypes.NewResource(&url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/",
			}),
			wantErr: assert.NoError,
		},
		{
			name: "error/there isn't a resource in the context",
			args: args{
				ctx: context.Background(),
			},
			want:    powValueTypes.Resource{},
			wantErr: assert.Error,
		},
		{
			name: "error/resource has an invalid type",
			args: args{
				ctx: context.WithValue(context.Background(), resourceCtxKey{}, "invalid"),
			},
			want:    powValueTypes.Resource{},
			wantErr: assert.Error,
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			got, err := (DynamicResource{}).ProvideResource(data.args.ctx)

			assert.Equal(test, data.want, got)
			data.wantErr(test, err)
		})
	}
}
