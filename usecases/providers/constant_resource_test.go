package dosProtectionUsecaseProviders

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	dosProtectionUsecases "github.com/thewizardplusplus/go-dos-protection/usecases"
	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

func TestConstantResource_interface(test *testing.T) {
	assert.Implements(
		test,
		(*dosProtectionUsecases.ResourceProvider)(nil),
		ConstantResource{},
	)
}

func TestNewConstantResource(test *testing.T) {
	type args struct {
		resource powValueTypes.Resource
	}

	for _, data := range []struct {
		name string
		args args
		want ConstantResource
	}{
		{
			name: "success",
			args: args{
				resource: powValueTypes.NewResource(&url.URL{
					Scheme: "https",
					Host:   "example.com",
					Path:   "/",
				}),
			},
			want: ConstantResource{
				resource: powValueTypes.NewResource(&url.URL{
					Scheme: "https",
					Host:   "example.com",
					Path:   "/",
				}),
			},
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			got := NewConstantResource(data.args.resource)

			assert.Equal(test, data.want, got)
		})
	}
}

func TestConstantResource_ProvideResource(test *testing.T) {
	type fields struct {
		resource powValueTypes.Resource
	}
	type args struct {
		ctx context.Context
	}

	for _, data := range []struct {
		name    string
		fields  fields
		args    args
		want    powValueTypes.Resource
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "success",
			fields: fields{
				resource: powValueTypes.NewResource(&url.URL{
					Scheme: "https",
					Host:   "example.com",
					Path:   "/",
				}),
			},
			args: args{
				ctx: context.Background(),
			},
			want: powValueTypes.NewResource(&url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/",
			}),
			wantErr: assert.NoError,
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			provider := ConstantResource{
				resource: data.fields.resource,
			}
			got, err := provider.ProvideResource(data.args.ctx)

			assert.Equal(test, data.want, got)
			data.wantErr(test, err)
		})
	}
}
