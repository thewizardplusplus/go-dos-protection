package dosProtectorUsecases

import (
	"bytes"
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
	dosProtectorUsecasesMocks "github.com/thewizardplusplus/go-dos-protector/mocks/github.com/thewizardplusplus/go-dos-protector/usecases"
	dosProtectorUsecaseErrors "github.com/thewizardplusplus/go-dos-protector/usecases/errors"
	dosProtectorUsecaseModels "github.com/thewizardplusplus/go-dos-protector/usecases/models"
	pow "github.com/thewizardplusplus/go-pow"
	powErrors "github.com/thewizardplusplus/go-pow/errors"
	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

func TestNewClientDoSProtectorUsecase(test *testing.T) {
	type args struct {
		options func(test *testing.T) ClientDoSProtectorUsecaseOptions
	}

	for _, data := range []struct {
		name string
		args args
		want func(test *testing.T) ClientDoSProtectorUsecase
	}{
		{
			name: "success",
			args: args{
				options: func(test *testing.T) ClientDoSProtectorUsecaseOptions {
					return ClientDoSProtectorUsecaseOptions{
						HashProvider: dosProtectorUsecasesMocks.NewMockHashProvider(test),
					}
				},
			},
			want: func(test *testing.T) ClientDoSProtectorUsecase {
				return ClientDoSProtectorUsecase{
					options: ClientDoSProtectorUsecaseOptions{
						HashProvider: dosProtectorUsecasesMocks.NewMockHashProvider(test),
					},
				}
			},
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			got := NewClientDoSProtectorUsecase(data.args.options(test))

			assert.Equal(test, data.want(test), got)
		})
	}
}

func TestClientDoSProtectorUsecase_SolveChallenge(test *testing.T) {
	type fields struct {
		options func(test *testing.T) ClientDoSProtectorUsecaseOptions
	}
	type args struct {
		ctx    context.Context
		params dosProtectorUsecaseModels.SolveChallengeParams
	}

	for _, data := range []struct {
		name    string
		fields  fields
		args    args
		want    pow.Solution
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "success/zero initial nonce",
			fields: fields{
				options: func(test *testing.T) ClientDoSProtectorUsecaseOptions {
					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ClientDoSProtectorUsecaseOptions{
						HashProvider: hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.SolveChallengeParams{
					LeadingZeroBitCount: 5,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 "876000h0m0s",
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
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
			name: "success/random initial nonce",
			fields: fields{
				options: func(test *testing.T) ClientDoSProtectorUsecaseOptions {
					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ClientDoSProtectorUsecaseOptions{
						HashProvider: hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.SolveChallengeParams{
					LeadingZeroBitCount: 5,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 "876000h0m0s",
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
					RandomInitialNonceParams: mo.Some(powValueTypes.RandomNonceParams{
						RandomReader: bytes.NewReader([]byte("dummy")),
						MinRawValue:  big.NewInt(123),
						MaxRawValue:  big.NewInt(142),
					}),
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
				rawHash.Write([]byte("5:dummy:129"))

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

				nonce, err := powValueTypes.NewNonce(big.NewInt(129))
				require.NoError(test, err)

				solution, err := pow.NewSolutionBuilder().
					SetChallenge(challenge).
					SetNonce(nonce).
					SetHashSum(powValueTypes.NewHashSum([]byte{
						0x01, 0x2b, 0x29, 0x61, 0x88, 0x31, 0x8c, 0xa1,
						0xe0, 0x93, 0x88, 0x91, 0x93, 0x32, 0x14, 0x48,
						0xd5, 0xd7, 0x11, 0x49, 0x46, 0xe6, 0x68, 0x1c,
						0x07, 0x75, 0xdb, 0x4c, 0xdc, 0x4e, 0x76, 0xb3,
					})).
					Build()
				require.NoError(test, err)

				return solution
			}(),
			wantErr: assert.NoError,
		},
		{
			name: "error/unable to construct the leading zero bit count",
			fields: fields{
				options: func(test *testing.T) ClientDoSProtectorUsecaseOptions {
					return ClientDoSProtectorUsecaseOptions{
						HashProvider: dosProtectorUsecasesMocks.NewMockHashProvider(test),
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.SolveChallengeParams{
					LeadingZeroBitCount: -23,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 "876000h0m0s",
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
				},
			},
			want: pow.Solution{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				target := dosProtectorUsecaseErrors.ErrInvalidParameters
				return assert.ErrorIs(test, err, target)
			},
		},
		{
			name: "error/unable to construct the `CreatedAt` timestamp",
			fields: fields{
				options: func(test *testing.T) ClientDoSProtectorUsecaseOptions {
					return ClientDoSProtectorUsecaseOptions{
						HashProvider: dosProtectorUsecasesMocks.NewMockHashProvider(test),
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.SolveChallengeParams{
					LeadingZeroBitCount: 5,
					CreatedAt:           "invalid",
					TTL:                 "876000h0m0s",
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
				},
			},
			want: pow.Solution{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				target := dosProtectorUsecaseErrors.ErrInvalidParameters
				return assert.ErrorIs(test, err, target)
			},
		},
		{
			name: "error/unable to parse the TTL",
			fields: fields{
				options: func(test *testing.T) ClientDoSProtectorUsecaseOptions {
					return ClientDoSProtectorUsecaseOptions{
						HashProvider: dosProtectorUsecasesMocks.NewMockHashProvider(test),
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.SolveChallengeParams{
					LeadingZeroBitCount: 5,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 "invalid",
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
				},
			},
			want: pow.Solution{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				target := dosProtectorUsecaseErrors.ErrInvalidParameters
				return assert.ErrorIs(test, err, target)
			},
		},
		{
			name: "error/unable to parse the resource",
			fields: fields{
				options: func(test *testing.T) ClientDoSProtectorUsecaseOptions {
					return ClientDoSProtectorUsecaseOptions{
						HashProvider: dosProtectorUsecasesMocks.NewMockHashProvider(test),
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.SolveChallengeParams{
					LeadingZeroBitCount: 5,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 "876000h0m0s",
					Resource:            ":",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
				},
			},
			want: pow.Solution{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				target := dosProtectorUsecaseErrors.ErrInvalidParameters
				return assert.ErrorIs(test, err, target)
			},
		},
		{
			name: "error/unable to get the hash by name",
			fields: fields{
				options: func(test *testing.T) ClientDoSProtectorUsecaseOptions {
					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.Hash{}, iotest.ErrTimeout)

					return ClientDoSProtectorUsecaseOptions{
						HashProvider: hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.SolveChallengeParams{
					LeadingZeroBitCount: 5,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 "876000h0m0s",
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
				},
			},
			want:    pow.Solution{},
			wantErr: assert.Error,
		},
		{
			name: "error/unable to parse the hash data layout",
			fields: fields{
				options: func(test *testing.T) ClientDoSProtectorUsecaseOptions {
					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ClientDoSProtectorUsecaseOptions{
						HashProvider: hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.SolveChallengeParams{
					LeadingZeroBitCount: 5,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 "876000h0m0s",
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout:      "dummy {{ .Dummy",
				},
			},
			want: pow.Solution{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				target := dosProtectorUsecaseErrors.ErrInvalidParameters
				return assert.ErrorIs(test, err, target)
			},
		},
		{
			name: "error/unable to build the challenge",
			fields: fields{
				options: func(test *testing.T) ClientDoSProtectorUsecaseOptions {
					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ClientDoSProtectorUsecaseOptions{
						HashProvider: hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.SolveChallengeParams{
					LeadingZeroBitCount: 1000,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 "876000h0m0s",
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
				},
			},
			want: pow.Solution{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				target := dosProtectorUsecaseErrors.ErrInvalidParameters
				return assert.ErrorIs(test, err, target)
			},
		},
		{
			name: "error/challenge is outdated",
			fields: fields{
				options: func(test *testing.T) ClientDoSProtectorUsecaseOptions {
					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ClientDoSProtectorUsecaseOptions{
						HashProvider: hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.SolveChallengeParams{
					LeadingZeroBitCount: 5,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 time.Second.String(),
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
				},
			},
			want: pow.Solution{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				return assert.ErrorIs(test, err, powErrors.ErrValidationFailure)
			},
		},
		{
			name: "error/" +
				"unable to solve the challenge/" +
				"unable to generate the random initial nonce/" +
				"regular error",
			fields: fields{
				options: func(test *testing.T) ClientDoSProtectorUsecaseOptions {
					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ClientDoSProtectorUsecaseOptions{
						HashProvider: hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.SolveChallengeParams{
					LeadingZeroBitCount: 5,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 "876000h0m0s",
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
					RandomInitialNonceParams: mo.Some(powValueTypes.RandomNonceParams{
						RandomReader: bytes.NewReader([]byte("dummy")),
						MinRawValue:  big.NewInt(142),
						MaxRawValue:  big.NewInt(123),
					}),
				},
			},
			want: pow.Solution{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				target := dosProtectorUsecaseErrors.ErrInvalidParameters
				return assert.ErrorIs(test, err, target)
			},
		},
		{
			name: "error/" +
				"unable to solve the challenge/" +
				"unable to generate the random initial nonce/" +
				"I/O error",
			fields: fields{
				options: func(test *testing.T) ClientDoSProtectorUsecaseOptions {
					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ClientDoSProtectorUsecaseOptions{
						HashProvider: hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.SolveChallengeParams{
					LeadingZeroBitCount: 5,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 "876000h0m0s",
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
					RandomInitialNonceParams: mo.Some(powValueTypes.RandomNonceParams{
						RandomReader: iotest.ErrReader(iotest.ErrTimeout),
						MinRawValue:  big.NewInt(123),
						MaxRawValue:  big.NewInt(142),
					}),
				},
			},
			want: pow.Solution{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				return assert.ErrorIs(test, err, powErrors.ErrIO)
			},
		},
		{
			name: "error/unable to solve the challenge/context is done",
			fields: fields{
				options: func(test *testing.T) ClientDoSProtectorUsecaseOptions {
					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(
							func() context.Context {
								ctx, ctxCancel := context.WithCancel(context.Background())
								ctxCancel()

								return ctx
							}(),
							"SHA-256",
						).
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ClientDoSProtectorUsecaseOptions{
						HashProvider: hashProviderMock,
					}
				},
			},
			args: args{
				ctx: func() context.Context {
					ctx, ctxCancel := context.WithCancel(context.Background())
					ctxCancel()

					return ctx
				}(),
				params: dosProtectorUsecaseModels.SolveChallengeParams{
					LeadingZeroBitCount: 5,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 "876000h0m0s",
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
				},
			},
			want: pow.Solution{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				return assert.ErrorIs(test, err, powErrors.ErrTaskInterruption)
			},
		},
		{
			name: "error/" +
				"unable to solve the challenge/" +
				"maximal attempt count is exceeded",
			fields: fields{
				options: func(test *testing.T) ClientDoSProtectorUsecaseOptions {
					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ClientDoSProtectorUsecaseOptions{
						HashProvider: hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.SolveChallengeParams{
					LeadingZeroBitCount: 5,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 "876000h0m0s",
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
					MaxAttemptCount: mo.Some(23),
				},
			},
			want: pow.Solution{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				return assert.ErrorIs(test, err, powErrors.ErrTaskInterruption)
			},
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			usecase := ClientDoSProtectorUsecase{
				options: data.fields.options(test),
			}
			got, err := usecase.SolveChallenge(data.args.ctx, data.args.params)

			assert.Equal(test, data.want, got)
			data.wantErr(test, err)
		})
	}
}
