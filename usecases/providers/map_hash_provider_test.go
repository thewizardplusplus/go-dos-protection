package dosProtectionUsecaseProviders

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	dosProtectionUsecases "github.com/thewizardplusplus/go-dos-protection/usecases"
	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

func TestMapHashProvider_interface(test *testing.T) {
	assert.Implements(
		test,
		(*dosProtectionUsecases.HashProvider)(nil),
		MapHashProvider{},
	)
}

func TestNewMapHashProvider(test *testing.T) {
	for _, data := range []struct {
		name string
		want MapHashProvider
	}{
		{
			name: "success",
			want: MapHashProvider{
				rawHashConstructorsByHashNames: make(map[string]RawHashConstructor),
			},
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			got := NewMapHashProvider()

			assert.Equal(test, data.want, got)
		})
	}
}

func TestMapHashProvider_RegisterHash(test *testing.T) {
	type fields struct {
		rawHashConstructorsByHashNames map[string]RawHashConstructor
	}
	type args struct {
		hashName           string
		rawHashConstructor RawHashConstructor
	}

	for _, data := range []struct {
		name          string
		fields        fields
		args          args
		wantHashNames []string
	}{
		{
			name: "success/unknown hash name",
			fields: fields{
				rawHashConstructorsByHashNames: map[string]RawHashConstructor{
					"dummy-one": sha256.New,
				},
			},
			args: args{
				hashName:           "dummy-two",
				rawHashConstructor: sha256.New,
			},
			wantHashNames: []string{"dummy-one", "dummy-two"},
		},
		{
			name: "success/known hash name",
			fields: fields{
				rawHashConstructorsByHashNames: map[string]RawHashConstructor{
					"dummy": sha256.New,
				},
			},
			args: args{
				hashName:           "dummy",
				rawHashConstructor: sha256.New,
			},
			wantHashNames: []string{"dummy"},
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			provider := MapHashProvider{
				rawHashConstructorsByHashNames: data.fields.rawHashConstructorsByHashNames,
			}
			provider.RegisterHash(data.args.hashName, data.args.rawHashConstructor)

			gotHashNames :=
				make([]string, 0, len(provider.rawHashConstructorsByHashNames))
			for hashName, rawHashConstructor := range provider.rawHashConstructorsByHashNames { //nolint:lll
				assert.NotNil(test, rawHashConstructor)

				gotHashNames = append(gotHashNames, hashName)
			}

			assert.ElementsMatch(test, data.wantHashNames, gotHashNames)
		})
	}
}

func TestMapHashProvider_ProvideHashByName(test *testing.T) {
	type fields struct {
		rawHashConstructorsByHashNames map[string]RawHashConstructor
	}
	type args struct {
		ctx      context.Context
		hashName string
	}

	for _, data := range []struct {
		name    string
		fields  fields
		args    args
		want    powValueTypes.Hash
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "success",
			fields: fields{
				rawHashConstructorsByHashNames: map[string]RawHashConstructor{
					"dummy": sha256.New,
				},
			},
			args: args{
				ctx:      context.Background(),
				hashName: "dummy",
			},
			want: func() powValueTypes.Hash {
				value, err := powValueTypes.NewHashWithName(sha256.New(), "dummy")
				require.NoError(test, err)

				return value
			}(),
			wantErr: assert.NoError,
		},
		{
			name: "error/unknown hash name",
			fields: fields{
				rawHashConstructorsByHashNames: map[string]RawHashConstructor{
					"dummy-one": sha256.New,
				},
			},
			args: args{
				ctx:      context.Background(),
				hashName: "dummy-two",
			},
			want:    powValueTypes.Hash{},
			wantErr: assert.Error,
		},
		{
			name: "error/unable to construct the hash",
			fields: fields{
				rawHashConstructorsByHashNames: map[string]RawHashConstructor{
					"": sha256.New,
				},
			},
			args: args{
				ctx:      context.Background(),
				hashName: "",
			},
			want:    powValueTypes.Hash{},
			wantErr: assert.Error,
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			provider := MapHashProvider{
				rawHashConstructorsByHashNames: data.fields.rawHashConstructorsByHashNames,
			}
			got, err := provider.ProvideHashByName(data.args.ctx, data.args.hashName)

			assert.Equal(test, data.want, got)
			data.wantErr(test, err)
		})
	}
}
