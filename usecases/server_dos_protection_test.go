package dosProtectionUsecases

import (
	"context"
	"crypto/sha256"
	"math/big"
	"net/url"
	"testing"
	"testing/iotest"
	"time"

	"github.com/samber/mo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	dosProtectionUsecasesMocks "github.com/thewizardplusplus/go-dos-protection/mocks/github.com/thewizardplusplus/go-dos-protection/usecases"
	dosProtectionUsecaseModels "github.com/thewizardplusplus/go-dos-protection/usecases/models"
	pow "github.com/thewizardplusplus/go-pow"
	powErrors "github.com/thewizardplusplus/go-pow/errors"
	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

func TestServerDoSProtectionUsecase_VerifySolution(test *testing.T) {
	type fields struct {
		options func(test *testing.T) ServerDoSProtectionUsecaseOptions
	}
	type args struct {
		ctx    context.Context
		params dosProtectionUsecaseModels.VerifySolutionParams
	}

	for _, data := range []struct {
		name    string
		fields  fields
		args    args
		want    pow.Solution
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "success/hash sum is present",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectionUsecaseOptions {
					resourceProviderMock :=
						dosProtectionUsecasesMocks.NewMockResourceProvider(test)
					resourceProviderMock.EXPECT().
						ProvideResource(context.Background()).
						Return(
							powValueTypes.NewResource(&url.URL{
								Scheme: "https",
								Host:   "example.com",
								Path:   "/",
							}),
							nil,
						)

					hashProviderMock := dosProtectionUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ServerDoSProtectionUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectionUsecaseModels.VerifySolutionParams{
					LeadingZeroBitCount: 5,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 (100 * 365 * 24 * time.Hour).String(),
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
					Nonce: "37",
					HashSum: mo.Some(
						"005d372c56e6c6b5" +
							"2ad4a8325654692e" +
							"c9aa3af5f7302174" +
							"8bc3fdb124ae9b20",
					),
				},
			},
			want: func() pow.Solution {
				leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(5)
				require.NoError(test, err)

				createdAt, err := powValueTypes.NewCreatedAt(
					time.Date(2000, time.January, 2, 3, 4, 5, 6, time.UTC),
				)
				require.NoError(test, err)

				ttl, err := powValueTypes.NewTTL(100 * 365 * 24 * time.Hour)
				require.NoError(test, err)

				rawHash := sha256.New()
				rawHash.Write([]byte("5:dummy:37"))

				challenge, err := pow.NewChallengeBuilder().
					SetLeadingZeroBitCount(leadingZeroBitCount).
					SetCreatedAt(createdAt).
					SetTTL(ttl).
					SetResource(powValueTypes.NewResource(&url.URL{
						Scheme: "https",
						Host:   "example.com",
						Path:   "/",
					})).
					SetSerializedPayload(powValueTypes.NewSerializedPayload("dummy")).
					SetHash(powValueTypes.NewHash(rawHash)).
					SetHashDataLayout(powValueTypes.MustParseHashDataLayout(
						"{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
							":{{ .Challenge.SerializedPayload.ToString }}" +
							":{{ .Nonce.ToString }}",
					)).
					Build()
				require.NoError(test, err)

				nonce, err := powValueTypes.NewNonce(big.NewInt(37))
				require.NoError(test, err)

				solution, err := pow.NewSolutionBuilder().
					SetChallenge(challenge).
					SetNonce(nonce).
					SetHashSum(powValueTypes.NewHashSum([]byte{
						0x00, 0x5d, 0x37, 0x2c, 0x56, 0xe6, 0xc6, 0xb5,
						0x2a, 0xd4, 0xa8, 0x32, 0x56, 0x54, 0x69, 0x2e,
						0xc9, 0xaa, 0x3a, 0xf5, 0xf7, 0x30, 0x21, 0x74,
						0x8b, 0xc3, 0xfd, 0xb1, 0x24, 0xae, 0x9b, 0x20,
					})).
					Build()
				require.NoError(test, err)

				return solution
			}(),
			wantErr: assert.NoError,
		},
		{
			name: "success/hash sum is absent",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectionUsecaseOptions {
					resourceProviderMock :=
						dosProtectionUsecasesMocks.NewMockResourceProvider(test)
					resourceProviderMock.EXPECT().
						ProvideResource(context.Background()).
						Return(
							powValueTypes.NewResource(&url.URL{
								Scheme: "https",
								Host:   "example.com",
								Path:   "/",
							}),
							nil,
						)

					hashProviderMock := dosProtectionUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ServerDoSProtectionUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectionUsecaseModels.VerifySolutionParams{
					LeadingZeroBitCount: 5,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 (100 * 365 * 24 * time.Hour).String(),
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
					Nonce:   "37",
					HashSum: mo.None[string](),
				},
			},
			want: func() pow.Solution {
				leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(5)
				require.NoError(test, err)

				createdAt, err := powValueTypes.NewCreatedAt(
					time.Date(2000, time.January, 2, 3, 4, 5, 6, time.UTC),
				)
				require.NoError(test, err)

				ttl, err := powValueTypes.NewTTL(100 * 365 * 24 * time.Hour)
				require.NoError(test, err)

				rawHash := sha256.New()
				rawHash.Write([]byte("5:dummy:37"))

				challenge, err := pow.NewChallengeBuilder().
					SetLeadingZeroBitCount(leadingZeroBitCount).
					SetCreatedAt(createdAt).
					SetTTL(ttl).
					SetResource(powValueTypes.NewResource(&url.URL{
						Scheme: "https",
						Host:   "example.com",
						Path:   "/",
					})).
					SetSerializedPayload(powValueTypes.NewSerializedPayload("dummy")).
					SetHash(powValueTypes.NewHash(rawHash)).
					SetHashDataLayout(powValueTypes.MustParseHashDataLayout(
						"{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
							":{{ .Challenge.SerializedPayload.ToString }}" +
							":{{ .Nonce.ToString }}",
					)).
					Build()
				require.NoError(test, err)

				nonce, err := powValueTypes.NewNonce(big.NewInt(37))
				require.NoError(test, err)

				solution, err := pow.NewSolutionBuilder().
					SetChallenge(challenge).
					SetNonce(nonce).
					Build()
				require.NoError(test, err)

				return solution
			}(),
			wantErr: assert.NoError,
		},
		{
			name: "error/unable to construct the leading zero bit count",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectionUsecaseOptions {
					resourceProviderMock :=
						dosProtectionUsecasesMocks.NewMockResourceProvider(test)
					return ServerDoSProtectionUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     dosProtectionUsecasesMocks.NewMockHashProvider(test),
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectionUsecaseModels.VerifySolutionParams{
					LeadingZeroBitCount: -23,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 (100 * 365 * 24 * time.Hour).String(),
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
					Nonce:   "37",
					HashSum: mo.None[string](),
				},
			},
			want:    pow.Solution{},
			wantErr: assert.Error,
		},
		{
			name: "error/unable to construct the `CreatedAt` timestamp",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectionUsecaseOptions {
					resourceProviderMock :=
						dosProtectionUsecasesMocks.NewMockResourceProvider(test)
					return ServerDoSProtectionUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     dosProtectionUsecasesMocks.NewMockHashProvider(test),
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectionUsecaseModels.VerifySolutionParams{
					LeadingZeroBitCount: 5,
					CreatedAt:           "invalid",
					TTL:                 (100 * 365 * 24 * time.Hour).String(),
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
					Nonce:   "37",
					HashSum: mo.None[string](),
				},
			},
			want:    pow.Solution{},
			wantErr: assert.Error,
		},
		{
			name: "error/unable to parse the TTL",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectionUsecaseOptions {
					resourceProviderMock :=
						dosProtectionUsecasesMocks.NewMockResourceProvider(test)
					return ServerDoSProtectionUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     dosProtectionUsecasesMocks.NewMockHashProvider(test),
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectionUsecaseModels.VerifySolutionParams{
					LeadingZeroBitCount: 5,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 "invalid",
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
					Nonce:   "37",
					HashSum: mo.None[string](),
				},
			},
			want:    pow.Solution{},
			wantErr: assert.Error,
		},
		{
			name: "error/unable to get the expected resource",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectionUsecaseOptions {
					resourceProviderMock :=
						dosProtectionUsecasesMocks.NewMockResourceProvider(test)
					resourceProviderMock.EXPECT().
						ProvideResource(context.Background()).
						Return(powValueTypes.Resource{}, iotest.ErrTimeout)

					return ServerDoSProtectionUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     dosProtectionUsecasesMocks.NewMockHashProvider(test),
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectionUsecaseModels.VerifySolutionParams{
					LeadingZeroBitCount: 5,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 (100 * 365 * 24 * time.Hour).String(),
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
					Nonce:   "37",
					HashSum: mo.None[string](),
				},
			},
			want:    pow.Solution{},
			wantErr: assert.Error,
		},
		{
			name: "error/unable to parse the resource",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectionUsecaseOptions {
					resourceProviderMock :=
						dosProtectionUsecasesMocks.NewMockResourceProvider(test)
					resourceProviderMock.EXPECT().
						ProvideResource(context.Background()).
						Return(
							powValueTypes.NewResource(&url.URL{
								Scheme: "https",
								Host:   "example.com",
								Path:   "/",
							}),
							nil,
						)

					return ServerDoSProtectionUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     dosProtectionUsecasesMocks.NewMockHashProvider(test),
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectionUsecaseModels.VerifySolutionParams{
					LeadingZeroBitCount: 5,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 (100 * 365 * 24 * time.Hour).String(),
					Resource:            ":",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
					Nonce:   "37",
					HashSum: mo.None[string](),
				},
			},
			want:    pow.Solution{},
			wantErr: assert.Error,
		},
		{
			name: "error/resource doesn't match the expected one",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectionUsecaseOptions {
					resourceProviderMock :=
						dosProtectionUsecasesMocks.NewMockResourceProvider(test)
					resourceProviderMock.EXPECT().
						ProvideResource(context.Background()).
						Return(
							powValueTypes.NewResource(&url.URL{
								Scheme: "https",
								Host:   "example.com",
								Path:   "/two",
							}),
							nil,
						)

					return ServerDoSProtectionUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     dosProtectionUsecasesMocks.NewMockHashProvider(test),
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectionUsecaseModels.VerifySolutionParams{
					LeadingZeroBitCount: 5,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 (100 * 365 * 24 * time.Hour).String(),
					Resource:            "https://example.com/one",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
					Nonce:   "37",
					HashSum: mo.None[string](),
				},
			},
			want: pow.Solution{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				return assert.ErrorIs(test, err, powErrors.ErrValidationFailure)
			},
		},
		{
			name: "error/unable to get the hash by name",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectionUsecaseOptions {
					resourceProviderMock :=
						dosProtectionUsecasesMocks.NewMockResourceProvider(test)
					resourceProviderMock.EXPECT().
						ProvideResource(context.Background()).
						Return(
							powValueTypes.NewResource(&url.URL{
								Scheme: "https",
								Host:   "example.com",
								Path:   "/",
							}),
							nil,
						)

					hashProviderMock := dosProtectionUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.Hash{}, iotest.ErrTimeout)

					return ServerDoSProtectionUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectionUsecaseModels.VerifySolutionParams{
					LeadingZeroBitCount: 5,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 (100 * 365 * 24 * time.Hour).String(),
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
					Nonce:   "37",
					HashSum: mo.None[string](),
				},
			},
			want:    pow.Solution{},
			wantErr: assert.Error,
		},
		{
			name: "error/unable to parse the hash data layout",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectionUsecaseOptions {
					resourceProviderMock :=
						dosProtectionUsecasesMocks.NewMockResourceProvider(test)
					resourceProviderMock.EXPECT().
						ProvideResource(context.Background()).
						Return(
							powValueTypes.NewResource(&url.URL{
								Scheme: "https",
								Host:   "example.com",
								Path:   "/",
							}),
							nil,
						)

					hashProviderMock := dosProtectionUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ServerDoSProtectionUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectionUsecaseModels.VerifySolutionParams{
					LeadingZeroBitCount: 5,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 (100 * 365 * 24 * time.Hour).String(),
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout:      "dummy {{ .Dummy",
					Nonce:               "37",
					HashSum:             mo.None[string](),
				},
			},
			want:    pow.Solution{},
			wantErr: assert.Error,
		},
		{
			name: "error/unable to build the challenge",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectionUsecaseOptions {
					resourceProviderMock :=
						dosProtectionUsecasesMocks.NewMockResourceProvider(test)
					resourceProviderMock.EXPECT().
						ProvideResource(context.Background()).
						Return(
							powValueTypes.NewResource(&url.URL{
								Scheme: "https",
								Host:   "example.com",
								Path:   "/",
							}),
							nil,
						)

					hashProviderMock := dosProtectionUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ServerDoSProtectionUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectionUsecaseModels.VerifySolutionParams{
					LeadingZeroBitCount: 1000,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 (100 * 365 * 24 * time.Hour).String(),
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
					Nonce:   "37",
					HashSum: mo.None[string](),
				},
			},
			want:    pow.Solution{},
			wantErr: assert.Error,
		},
		{
			name: "error/challenge is outdated",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectionUsecaseOptions {
					resourceProviderMock :=
						dosProtectionUsecasesMocks.NewMockResourceProvider(test)
					resourceProviderMock.EXPECT().
						ProvideResource(context.Background()).
						Return(
							powValueTypes.NewResource(&url.URL{
								Scheme: "https",
								Host:   "example.com",
								Path:   "/",
							}),
							nil,
						)

					hashProviderMock := dosProtectionUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ServerDoSProtectionUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectionUsecaseModels.VerifySolutionParams{
					LeadingZeroBitCount: 5,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 time.Second.String(),
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
					Nonce:   "37",
					HashSum: mo.None[string](),
				},
			},
			want: pow.Solution{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				return assert.ErrorIs(test, err, powErrors.ErrValidationFailure)
			},
		},
		{
			name: "error/unable to parse the nonce",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectionUsecaseOptions {
					resourceProviderMock :=
						dosProtectionUsecasesMocks.NewMockResourceProvider(test)
					resourceProviderMock.EXPECT().
						ProvideResource(context.Background()).
						Return(
							powValueTypes.NewResource(&url.URL{
								Scheme: "https",
								Host:   "example.com",
								Path:   "/",
							}),
							nil,
						)

					hashProviderMock := dosProtectionUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ServerDoSProtectionUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectionUsecaseModels.VerifySolutionParams{
					LeadingZeroBitCount: 5,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 (100 * 365 * 24 * time.Hour).String(),
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
					Nonce:   "invalid",
					HashSum: mo.None[string](),
				},
			},
			want:    pow.Solution{},
			wantErr: assert.Error,
		},
		{
			name: "error/unable to parse the hash sum",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectionUsecaseOptions {
					resourceProviderMock :=
						dosProtectionUsecasesMocks.NewMockResourceProvider(test)
					resourceProviderMock.EXPECT().
						ProvideResource(context.Background()).
						Return(
							powValueTypes.NewResource(&url.URL{
								Scheme: "https",
								Host:   "example.com",
								Path:   "/",
							}),
							nil,
						)

					hashProviderMock := dosProtectionUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ServerDoSProtectionUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectionUsecaseModels.VerifySolutionParams{
					LeadingZeroBitCount: 5,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 (100 * 365 * 24 * time.Hour).String(),
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
					Nonce:   "37",
					HashSum: mo.Some("invalid"),
				},
			},
			want:    pow.Solution{},
			wantErr: assert.Error,
		},
		{
			name: "error/unable to build the solution",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectionUsecaseOptions {
					resourceProviderMock :=
						dosProtectionUsecasesMocks.NewMockResourceProvider(test)
					resourceProviderMock.EXPECT().
						ProvideResource(context.Background()).
						Return(
							powValueTypes.NewResource(&url.URL{
								Scheme: "https",
								Host:   "example.com",
								Path:   "/",
							}),
							nil,
						)

					hashProviderMock := dosProtectionUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ServerDoSProtectionUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectionUsecaseModels.VerifySolutionParams{
					LeadingZeroBitCount: 5,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 (100 * 365 * 24 * time.Hour).String(),
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
					Nonce: "37",
					HashSum: mo.Some(
						"005d372c56e6c6b5" +
							"2ad4a8325654692e",
					),
				},
			},
			want:    pow.Solution{},
			wantErr: assert.Error,
		},
		{
			name: "error/unable to verify the solution",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectionUsecaseOptions {
					resourceProviderMock :=
						dosProtectionUsecasesMocks.NewMockResourceProvider(test)
					resourceProviderMock.EXPECT().
						ProvideResource(context.Background()).
						Return(
							powValueTypes.NewResource(&url.URL{
								Scheme: "https",
								Host:   "example.com",
								Path:   "/",
							}),
							nil,
						)

					hashProviderMock := dosProtectionUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ServerDoSProtectionUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectionUsecaseModels.VerifySolutionParams{
					LeadingZeroBitCount: 23,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 (100 * 365 * 24 * time.Hour).String(),
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
					Nonce: "37",
					HashSum: mo.Some(
						"005d372c56e6c6b5" +
							"2ad4a8325654692e" +
							"c9aa3af5f7302174" +
							"8bc3fdb124ae9b20",
					),
				},
			},
			want: pow.Solution{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				return assert.ErrorIs(test, err, powErrors.ErrValidationFailure)
			},
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			usecase := ServerDoSProtectionUsecase{
				options: data.fields.options(test),
			}
			got, err := usecase.VerifySolution(data.args.ctx, data.args.params)

			assert.Equal(test, data.want, got)
			data.wantErr(test, err)
		})
	}
}
