package dosProtectorUsecases

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"math/big"
	"net/url"
	"strings"
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

func TestNewServerDoSProtectorUsecase(test *testing.T) {
	type args struct {
		options func(test *testing.T) ServerDoSProtectorUsecaseOptions
	}

	for _, data := range []struct {
		name string
		args args
		want func(test *testing.T) ServerDoSProtectorUsecase
	}{
		{
			name: "success",
			args: args{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					ttl, err := powValueTypes.NewTTL(100 * 365 * 24 * time.Hour)
					require.NoError(test, err)

					leadingZeroBitCountProviderMock :=
						dosProtectorUsecasesMocks.NewMockLeadingZeroBitCountProvider(test)
					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
					serializedPayloadProviderMock :=
						dosProtectorUsecasesMocks.NewMockSerializedPayloadProvider(test)
					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					return ServerDoSProtectorUsecaseOptions{
						LeadingZeroBitCountProvider:   leadingZeroBitCountProviderMock,
						CreatedAtModulus:              10 * time.Minute,
						TTL:                           ttl,
						ResourceProvider:              resourceProviderMock,
						MainSerializedPayloadProvider: serializedPayloadProviderMock,
						RandomPayloadByteReader:       strings.NewReader("0123456789"),
						RandomPayloadByteCount:        5,
						HashProvider:                  hashProviderMock,
						GenerationHashName:            "SHA-256",
						SecretKey:                     "secret-key",
						SigningHashName:               "SHA-512",
					}
				},
			},
			want: func(test *testing.T) ServerDoSProtectorUsecase {
				ttl, err := powValueTypes.NewTTL(100 * 365 * 24 * time.Hour)
				require.NoError(test, err)

				leadingZeroBitCountProviderMock :=
					dosProtectorUsecasesMocks.NewMockLeadingZeroBitCountProvider(test)
				resourceProviderMock :=
					dosProtectorUsecasesMocks.NewMockResourceProvider(test)
				serializedPayloadProviderMock :=
					dosProtectorUsecasesMocks.NewMockSerializedPayloadProvider(test)
				hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
				return ServerDoSProtectorUsecase{
					options: ServerDoSProtectorUsecaseOptions{
						LeadingZeroBitCountProvider:   leadingZeroBitCountProviderMock,
						CreatedAtModulus:              10 * time.Minute,
						TTL:                           ttl,
						ResourceProvider:              resourceProviderMock,
						MainSerializedPayloadProvider: serializedPayloadProviderMock,
						RandomPayloadByteReader:       strings.NewReader("0123456789"),
						RandomPayloadByteCount:        5,
						HashProvider:                  hashProviderMock,
						GenerationHashName:            "SHA-256",
						SecretKey:                     "secret-key",
						SigningHashName:               "SHA-512",
					},
				}
			},
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			got := NewServerDoSProtectorUsecase(data.args.options(test))

			assert.Equal(test, data.want(test), got)
		})
	}
}

func TestServerDoSProtectorUsecase_SignChallenge(test *testing.T) {
	type fields struct {
		options func(test *testing.T) ServerDoSProtectorUsecaseOptions
	}
	type args struct {
		ctx       context.Context
		challenge pow.Challenge
	}

	for _, data := range []struct {
		name    string
		fields  fields
		args    args
		want    powValueTypes.HashSum
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "success/all parameters",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-512").
						Return(powValueTypes.NewHash(sha512.New()), nil)

					return ServerDoSProtectorUsecaseOptions{
						HashProvider:    hashProviderMock,
						SecretKey:       "secret-key",
						SigningHashName: "SHA-512",
					}
				},
			},
			args: args{
				ctx: context.Background(),
				challenge: func() pow.Challenge {
					leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(5)
					require.NoError(test, err)

					createdAt, err := powValueTypes.NewCreatedAt(
						time.Date(2000, time.January, 2, 3, 4, 5, 6, time.UTC),
					)
					require.NoError(test, err)

					ttl, err := powValueTypes.NewTTL(100 * 365 * 24 * time.Hour)
					require.NoError(test, err)

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
						SetHash(powValueTypes.NewHash(sha256.New())).
						SetHashDataLayout(powValueTypes.MustParseHashDataLayout(
							"{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
								":{{ .Challenge.SerializedPayload.ToString }}" +
								":{{ .Nonce.ToString }}",
						)).
						Build()
					require.NoError(test, err)

					return challenge
				}(),
			},
			want: powValueTypes.NewHashSum([]byte{
				0x4b, 0x4f, 0x54, 0x7d, 0x39, 0xc5, 0x28, 0x03,
				0x44, 0xca, 0xc1, 0x9f, 0x32, 0x73, 0x2a, 0x5c,
				0x67, 0x7a, 0x1f, 0x21, 0x76, 0x3e, 0xae, 0xdd,
				0x0e, 0x21, 0xe9, 0x39, 0x34, 0x99, 0x91, 0x86,
				0xa6, 0x2f, 0xd7, 0x1e, 0x05, 0x78, 0xc8, 0x3d,
				0xb1, 0x37, 0xbe, 0x90, 0x30, 0xee, 0xa3, 0x0b,
				0x77, 0x2c, 0x09, 0x19, 0xcc, 0x98, 0xfc, 0xf9,
				0xf4, 0x28, 0x5b, 0x78, 0xc2, 0xd7, 0x8b, 0xa9,
			}),
			wantErr: assert.NoError,
		},
		{
			name: "success/required parameters only",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-512").
						Return(powValueTypes.NewHash(sha512.New()), nil)

					return ServerDoSProtectorUsecaseOptions{
						HashProvider:    hashProviderMock,
						SecretKey:       "secret-key",
						SigningHashName: "SHA-512",
					}
				},
			},
			args: args{
				ctx: context.Background(),
				challenge: func() pow.Challenge {
					leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(5)
					require.NoError(test, err)

					challenge, err := pow.NewChallengeBuilder().
						SetLeadingZeroBitCount(leadingZeroBitCount).
						SetSerializedPayload(powValueTypes.NewSerializedPayload("dummy")).
						SetHash(powValueTypes.NewHash(sha256.New())).
						SetHashDataLayout(powValueTypes.MustParseHashDataLayout(
							"{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
								":{{ .Challenge.SerializedPayload.ToString }}" +
								":{{ .Nonce.ToString }}",
						)).
						Build()
					require.NoError(test, err)

					return challenge
				}(),
			},
			want: powValueTypes.NewHashSum([]byte{
				0x69, 0xa9, 0x45, 0x3e, 0x55, 0xcb, 0x67, 0x40,
				0x0d, 0x42, 0xe0, 0x35, 0x58, 0x2c, 0x12, 0xb1,
				0x19, 0x2d, 0xaf, 0x54, 0x2a, 0xe7, 0x35, 0xe8,
				0x04, 0x08, 0x17, 0xa3, 0x0e, 0x0d, 0x10, 0x90,
				0xf5, 0xdd, 0x4a, 0x2a, 0x17, 0xae, 0x26, 0x9a,
				0xef, 0xe1, 0x5b, 0xd7, 0xd2, 0x1f, 0x68, 0x93,
				0x8d, 0xd2, 0x38, 0x9e, 0x25, 0x37, 0x9f, 0x9c,
				0xf9, 0x81, 0x89, 0xbe, 0x8f, 0x29, 0x73, 0x3e,
			}),
			wantErr: assert.NoError,
		},
		{
			name: "error",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-512").
						Return(powValueTypes.Hash{}, iotest.ErrTimeout)

					return ServerDoSProtectorUsecaseOptions{
						HashProvider:    hashProviderMock,
						SecretKey:       "secret-key",
						SigningHashName: "SHA-512",
					}
				},
			},
			args: args{
				ctx: context.Background(),
				challenge: func() pow.Challenge {
					leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(5)
					require.NoError(test, err)

					challenge, err := pow.NewChallengeBuilder().
						SetLeadingZeroBitCount(leadingZeroBitCount).
						SetSerializedPayload(powValueTypes.NewSerializedPayload("dummy")).
						SetHash(powValueTypes.NewHash(sha256.New())).
						SetHashDataLayout(powValueTypes.MustParseHashDataLayout(
							"{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
								":{{ .Challenge.SerializedPayload.ToString }}" +
								":{{ .Nonce.ToString }}",
						)).
						Build()
					require.NoError(test, err)

					return challenge
				}(),
			},
			want:    powValueTypes.HashSum{},
			wantErr: assert.Error,
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			usecase := ServerDoSProtectorUsecase{
				options: data.fields.options(test),
			}
			got, err := usecase.SignChallenge(data.args.ctx, data.args.challenge)

			assert.Equal(test, data.want, got)
			data.wantErr(test, err)
		})
	}
}

func TestServerDoSProtectorUsecase_GenerateChallenge(test *testing.T) {
	type fields struct {
		options func(test *testing.T) ServerDoSProtectorUsecaseOptions
	}
	type args struct {
		ctx context.Context
	}

	for _, data := range []struct {
		name    string
		fields  fields
		args    args
		want    pow.Challenge
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "success",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(5)
					require.NoError(test, err)

					leadingZeroBitCountProviderMock :=
						dosProtectorUsecasesMocks.NewMockLeadingZeroBitCountProvider(test)
					leadingZeroBitCountProviderMock.EXPECT().
						ProvideLeadingZeroBitCount(context.Background()).
						Return(leadingZeroBitCount, nil)

					ttl, err := powValueTypes.NewTTL(100 * 365 * 24 * time.Hour)
					require.NoError(test, err)

					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
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

					serializedPayloadProviderMock :=
						dosProtectorUsecasesMocks.NewMockSerializedPayloadProvider(test)
					serializedPayloadProviderMock.EXPECT().
						ProvideSerializedPayload(context.Background()).
						Return(powValueTypes.NewSerializedPayload("dummy"), nil)

					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ServerDoSProtectorUsecaseOptions{
						LeadingZeroBitCountProvider:   leadingZeroBitCountProviderMock,
						CreatedAtModulus:              10 * time.Minute,
						TTL:                           ttl,
						ResourceProvider:              resourceProviderMock,
						MainSerializedPayloadProvider: serializedPayloadProviderMock,
						RandomPayloadByteReader:       strings.NewReader("0123456789"),
						RandomPayloadByteCount:        5,
						HashProvider:                  hashProviderMock,
						GenerationHashName:            "SHA-256",
					}
				},
			},
			args: args{
				ctx: context.Background(),
			},
			want: func() pow.Challenge {
				leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(5)
				require.NoError(test, err)

				rawCreatedAt := time.Now().In(time.UTC).Truncate(10 * time.Minute)
				createdAt, err := powValueTypes.NewCreatedAt(rawCreatedAt)
				require.NoError(test, err)

				ttl, err := powValueTypes.NewTTL(100 * 365 * 24 * time.Hour)
				require.NoError(test, err)

				challenge, err := pow.NewChallengeBuilder().
					SetLeadingZeroBitCount(leadingZeroBitCount).
					SetCreatedAt(createdAt).
					SetTTL(ttl).
					SetResource(powValueTypes.NewResource(&url.URL{
						Scheme: "https",
						Host:   "example.com",
						Path:   "/",
					})).
					SetSerializedPayload(powValueTypes.NewSerializedPayload(
						"dummy3031323334",
					)).
					SetHash(powValueTypes.NewHash(sha256.New())).
					SetHashDataLayout(powValueTypes.MustParseHashDataLayout(
						"{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
							"{{ .Challenge.CreatedAt.MustGet.ToString }}" +
							"{{ .Challenge.TTL.MustGet.ToString }}" +
							"{{ .Challenge.Resource.MustGet.ToString }}" +
							"{{ .Challenge.SerializedPayload.ToString }}" +
							"{{ .Challenge.Hash.Name }}" +
							"{{ .Challenge.HashDataLayout.ToString }}" +
							"{{ .Nonce.ToString }}",
					)).
					Build()
				require.NoError(test, err)

				return challenge
			}(),
			wantErr: assert.NoError,
		},
		{
			name: "error/unable to get the leading zero bit count",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					leadingZeroBitCountProviderMock :=
						dosProtectorUsecasesMocks.NewMockLeadingZeroBitCountProvider(test)
					leadingZeroBitCountProviderMock.EXPECT().
						ProvideLeadingZeroBitCount(context.Background()).
						Return(powValueTypes.LeadingZeroBitCount{}, iotest.ErrTimeout)

					ttl, err := powValueTypes.NewTTL(100 * 365 * 24 * time.Hour)
					require.NoError(test, err)

					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
					serializedPayloadProviderMock :=
						dosProtectorUsecasesMocks.NewMockSerializedPayloadProvider(test)
					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					return ServerDoSProtectorUsecaseOptions{
						LeadingZeroBitCountProvider:   leadingZeroBitCountProviderMock,
						CreatedAtModulus:              10 * time.Minute,
						TTL:                           ttl,
						ResourceProvider:              resourceProviderMock,
						MainSerializedPayloadProvider: serializedPayloadProviderMock,
						RandomPayloadByteReader:       strings.NewReader("0123456789"),
						RandomPayloadByteCount:        5,
						HashProvider:                  hashProviderMock,
						GenerationHashName:            "SHA-256",
					}
				},
			},
			args: args{
				ctx: context.Background(),
			},
			want:    pow.Challenge{},
			wantErr: assert.Error,
		},
		{
			name: "error/unable to get the resource",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(5)
					require.NoError(test, err)

					leadingZeroBitCountProviderMock :=
						dosProtectorUsecasesMocks.NewMockLeadingZeroBitCountProvider(test)
					leadingZeroBitCountProviderMock.EXPECT().
						ProvideLeadingZeroBitCount(context.Background()).
						Return(leadingZeroBitCount, nil)

					ttl, err := powValueTypes.NewTTL(100 * 365 * 24 * time.Hour)
					require.NoError(test, err)

					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
					resourceProviderMock.EXPECT().
						ProvideResource(context.Background()).
						Return(powValueTypes.Resource{}, iotest.ErrTimeout)

					serializedPayloadProviderMock :=
						dosProtectorUsecasesMocks.NewMockSerializedPayloadProvider(test)
					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					return ServerDoSProtectorUsecaseOptions{
						LeadingZeroBitCountProvider:   leadingZeroBitCountProviderMock,
						CreatedAtModulus:              10 * time.Minute,
						TTL:                           ttl,
						ResourceProvider:              resourceProviderMock,
						MainSerializedPayloadProvider: serializedPayloadProviderMock,
						RandomPayloadByteReader:       strings.NewReader("0123456789"),
						RandomPayloadByteCount:        5,
						HashProvider:                  hashProviderMock,
						GenerationHashName:            "SHA-256",
					}
				},
			},
			args: args{
				ctx: context.Background(),
			},
			want:    pow.Challenge{},
			wantErr: assert.Error,
		},
		{
			name: "error/unable to get the main serialized payload",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(5)
					require.NoError(test, err)

					leadingZeroBitCountProviderMock :=
						dosProtectorUsecasesMocks.NewMockLeadingZeroBitCountProvider(test)
					leadingZeroBitCountProviderMock.EXPECT().
						ProvideLeadingZeroBitCount(context.Background()).
						Return(leadingZeroBitCount, nil)

					ttl, err := powValueTypes.NewTTL(100 * 365 * 24 * time.Hour)
					require.NoError(test, err)

					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
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

					serializedPayloadProviderMock :=
						dosProtectorUsecasesMocks.NewMockSerializedPayloadProvider(test)
					serializedPayloadProviderMock.EXPECT().
						ProvideSerializedPayload(context.Background()).
						Return(powValueTypes.SerializedPayload{}, iotest.ErrTimeout)

					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					return ServerDoSProtectorUsecaseOptions{
						LeadingZeroBitCountProvider:   leadingZeroBitCountProviderMock,
						CreatedAtModulus:              10 * time.Minute,
						TTL:                           ttl,
						ResourceProvider:              resourceProviderMock,
						MainSerializedPayloadProvider: serializedPayloadProviderMock,
						RandomPayloadByteReader:       strings.NewReader("0123456789"),
						RandomPayloadByteCount:        5,
						HashProvider:                  hashProviderMock,
						GenerationHashName:            "SHA-256",
					}
				},
			},
			args: args{
				ctx: context.Background(),
			},
			want:    pow.Challenge{},
			wantErr: assert.Error,
		},
		{
			name: "error/unable to read the random payload bytes",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(5)
					require.NoError(test, err)

					leadingZeroBitCountProviderMock :=
						dosProtectorUsecasesMocks.NewMockLeadingZeroBitCountProvider(test)
					leadingZeroBitCountProviderMock.EXPECT().
						ProvideLeadingZeroBitCount(context.Background()).
						Return(leadingZeroBitCount, nil)

					ttl, err := powValueTypes.NewTTL(100 * 365 * 24 * time.Hour)
					require.NoError(test, err)

					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
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

					serializedPayloadProviderMock :=
						dosProtectorUsecasesMocks.NewMockSerializedPayloadProvider(test)
					serializedPayloadProviderMock.EXPECT().
						ProvideSerializedPayload(context.Background()).
						Return(powValueTypes.NewSerializedPayload("dummy"), nil)

					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					return ServerDoSProtectorUsecaseOptions{
						LeadingZeroBitCountProvider:   leadingZeroBitCountProviderMock,
						CreatedAtModulus:              10 * time.Minute,
						TTL:                           ttl,
						ResourceProvider:              resourceProviderMock,
						MainSerializedPayloadProvider: serializedPayloadProviderMock,
						RandomPayloadByteReader:       iotest.ErrReader(iotest.ErrTimeout),
						RandomPayloadByteCount:        5,
						HashProvider:                  hashProviderMock,
						GenerationHashName:            "SHA-256",
					}
				},
			},
			args: args{
				ctx: context.Background(),
			},
			want: pow.Challenge{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				return assert.ErrorIs(test, err, powErrors.ErrIO)
			},
		},
		{
			name: "error/unable to get the hash by name",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(5)
					require.NoError(test, err)

					leadingZeroBitCountProviderMock :=
						dosProtectorUsecasesMocks.NewMockLeadingZeroBitCountProvider(test)
					leadingZeroBitCountProviderMock.EXPECT().
						ProvideLeadingZeroBitCount(context.Background()).
						Return(leadingZeroBitCount, nil)

					ttl, err := powValueTypes.NewTTL(100 * 365 * 24 * time.Hour)
					require.NoError(test, err)

					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
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

					serializedPayloadProviderMock :=
						dosProtectorUsecasesMocks.NewMockSerializedPayloadProvider(test)
					serializedPayloadProviderMock.EXPECT().
						ProvideSerializedPayload(context.Background()).
						Return(powValueTypes.NewSerializedPayload("dummy"), nil)

					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.Hash{}, iotest.ErrTimeout)

					return ServerDoSProtectorUsecaseOptions{
						LeadingZeroBitCountProvider:   leadingZeroBitCountProviderMock,
						CreatedAtModulus:              10 * time.Minute,
						TTL:                           ttl,
						ResourceProvider:              resourceProviderMock,
						MainSerializedPayloadProvider: serializedPayloadProviderMock,
						RandomPayloadByteReader:       strings.NewReader("0123456789"),
						RandomPayloadByteCount:        5,
						HashProvider:                  hashProviderMock,
						GenerationHashName:            "SHA-256",
					}
				},
			},
			args: args{
				ctx: context.Background(),
			},
			want:    pow.Challenge{},
			wantErr: assert.Error,
		},
		{
			name: "error/unable to build the challenge",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(1000)
					require.NoError(test, err)

					leadingZeroBitCountProviderMock :=
						dosProtectorUsecasesMocks.NewMockLeadingZeroBitCountProvider(test)
					leadingZeroBitCountProviderMock.EXPECT().
						ProvideLeadingZeroBitCount(context.Background()).
						Return(leadingZeroBitCount, nil)

					ttl, err := powValueTypes.NewTTL(100 * 365 * 24 * time.Hour)
					require.NoError(test, err)

					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
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

					serializedPayloadProviderMock :=
						dosProtectorUsecasesMocks.NewMockSerializedPayloadProvider(test)
					serializedPayloadProviderMock.EXPECT().
						ProvideSerializedPayload(context.Background()).
						Return(powValueTypes.NewSerializedPayload("dummy"), nil)

					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ServerDoSProtectorUsecaseOptions{
						LeadingZeroBitCountProvider:   leadingZeroBitCountProviderMock,
						CreatedAtModulus:              10 * time.Minute,
						TTL:                           ttl,
						ResourceProvider:              resourceProviderMock,
						MainSerializedPayloadProvider: serializedPayloadProviderMock,
						RandomPayloadByteReader:       strings.NewReader("0123456789"),
						RandomPayloadByteCount:        5,
						HashProvider:                  hashProviderMock,
						GenerationHashName:            "SHA-256",
					}
				},
			},
			args: args{
				ctx: context.Background(),
			},
			want:    pow.Challenge{},
			wantErr: assert.Error,
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			usecase := ServerDoSProtectorUsecase{
				options: data.fields.options(test),
			}
			got, err := usecase.GenerateChallenge(data.args.ctx)

			assert.Equal(test, data.want, got)
			data.wantErr(test, err)
		})
	}
}

func TestServerDoSProtectorUsecase_GenerateSignedChallenge(test *testing.T) {
	type fields struct {
		options func(test *testing.T) ServerDoSProtectorUsecaseOptions
	}
	type args struct {
		ctx context.Context
	}

	for _, data := range []struct {
		name    string
		fields  fields
		args    args
		want    dosProtectorUsecaseModels.SignedChallenge
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "success",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(5)
					require.NoError(test, err)

					leadingZeroBitCountProviderMock :=
						dosProtectorUsecasesMocks.NewMockLeadingZeroBitCountProvider(test)
					leadingZeroBitCountProviderMock.EXPECT().
						ProvideLeadingZeroBitCount(context.Background()).
						Return(leadingZeroBitCount, nil)

					ttl, err := powValueTypes.NewTTL(100 * 365 * 24 * time.Hour)
					require.NoError(test, err)

					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
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

					serializedPayloadProviderMock :=
						dosProtectorUsecasesMocks.NewMockSerializedPayloadProvider(test)
					serializedPayloadProviderMock.EXPECT().
						ProvideSerializedPayload(context.Background()).
						Return(powValueTypes.NewSerializedPayload("dummy"), nil)

					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-512").
						Return(powValueTypes.NewHash(sha512.New()), nil)

					return ServerDoSProtectorUsecaseOptions{
						LeadingZeroBitCountProvider:   leadingZeroBitCountProviderMock,
						CreatedAtModulus:              100 * 365 * 24 * time.Hour,
						TTL:                           ttl,
						ResourceProvider:              resourceProviderMock,
						MainSerializedPayloadProvider: serializedPayloadProviderMock,
						RandomPayloadByteReader:       strings.NewReader("0123456789"),
						RandomPayloadByteCount:        5,
						HashProvider:                  hashProviderMock,
						GenerationHashName:            "SHA-256",
						SecretKey:                     "secret-key",
						SigningHashName:               "SHA-512",
					}
				},
			},
			args: args{
				ctx: context.Background(),
			},
			want: func() dosProtectorUsecaseModels.SignedChallenge {
				leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(5)
				require.NoError(test, err)

				rawCreatedAt := time.Now().In(time.UTC).Truncate(100 * 365 * 24 * time.Hour)
				createdAt, err := powValueTypes.NewCreatedAt(rawCreatedAt)
				require.NoError(test, err)

				ttl, err := powValueTypes.NewTTL(100 * 365 * 24 * time.Hour)
				require.NoError(test, err)

				challenge, err := pow.NewChallengeBuilder().
					SetLeadingZeroBitCount(leadingZeroBitCount).
					SetCreatedAt(createdAt).
					SetTTL(ttl).
					SetResource(powValueTypes.NewResource(&url.URL{
						Scheme: "https",
						Host:   "example.com",
						Path:   "/",
					})).
					SetSerializedPayload(powValueTypes.NewSerializedPayload(
						"dummy3031323334",
					)).
					SetHash(powValueTypes.NewHash(sha256.New())).
					SetHashDataLayout(powValueTypes.MustParseHashDataLayout(
						"{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
							"{{ .Challenge.CreatedAt.MustGet.ToString }}" +
							"{{ .Challenge.TTL.MustGet.ToString }}" +
							"{{ .Challenge.Resource.MustGet.ToString }}" +
							"{{ .Challenge.SerializedPayload.ToString }}" +
							"{{ .Challenge.Hash.Name }}" +
							"{{ .Challenge.HashDataLayout.ToString }}" +
							"{{ .Nonce.ToString }}",
					)).
					Build()
				require.NoError(test, err)

				return dosProtectorUsecaseModels.SignedChallenge{
					Challenge: challenge,
					Signature: "ac163758d5bdd980" +
						"c712c64b6cbcf0d6" +
						"9e868b3f7da5dfda" +
						"58703eee68cf1db5" +
						"3bc319571e09cc63" +
						"f01bbffcbdd441ce" +
						"43f14fe262706c98" +
						"5a62d4019de6b661",
				}
			}(),
			wantErr: assert.NoError,
		},
		{
			name: "error/unable to generate the challenge/regular error",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(1000)
					require.NoError(test, err)

					leadingZeroBitCountProviderMock :=
						dosProtectorUsecasesMocks.NewMockLeadingZeroBitCountProvider(test)
					leadingZeroBitCountProviderMock.EXPECT().
						ProvideLeadingZeroBitCount(context.Background()).
						Return(leadingZeroBitCount, nil)

					ttl, err := powValueTypes.NewTTL(100 * 365 * 24 * time.Hour)
					require.NoError(test, err)

					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
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

					serializedPayloadProviderMock :=
						dosProtectorUsecasesMocks.NewMockSerializedPayloadProvider(test)
					serializedPayloadProviderMock.EXPECT().
						ProvideSerializedPayload(context.Background()).
						Return(powValueTypes.NewSerializedPayload("dummy"), nil)

					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ServerDoSProtectorUsecaseOptions{
						LeadingZeroBitCountProvider:   leadingZeroBitCountProviderMock,
						CreatedAtModulus:              10 * time.Minute,
						TTL:                           ttl,
						ResourceProvider:              resourceProviderMock,
						MainSerializedPayloadProvider: serializedPayloadProviderMock,
						RandomPayloadByteReader:       strings.NewReader("0123456789"),
						RandomPayloadByteCount:        5,
						HashProvider:                  hashProviderMock,
						GenerationHashName:            "SHA-256",
						SecretKey:                     "secret-key",
						SigningHashName:               "SHA-512",
					}
				},
			},
			args: args{
				ctx: context.Background(),
			},
			want:    dosProtectorUsecaseModels.SignedChallenge{},
			wantErr: assert.Error,
		},
		{
			name: "error/" +
				"unable to generate the challenge/" +
				"unable to read the random payload bytes",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(5)
					require.NoError(test, err)

					leadingZeroBitCountProviderMock :=
						dosProtectorUsecasesMocks.NewMockLeadingZeroBitCountProvider(test)
					leadingZeroBitCountProviderMock.EXPECT().
						ProvideLeadingZeroBitCount(context.Background()).
						Return(leadingZeroBitCount, nil)

					ttl, err := powValueTypes.NewTTL(100 * 365 * 24 * time.Hour)
					require.NoError(test, err)

					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
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

					serializedPayloadProviderMock :=
						dosProtectorUsecasesMocks.NewMockSerializedPayloadProvider(test)
					serializedPayloadProviderMock.EXPECT().
						ProvideSerializedPayload(context.Background()).
						Return(powValueTypes.NewSerializedPayload("dummy"), nil)

					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					return ServerDoSProtectorUsecaseOptions{
						LeadingZeroBitCountProvider:   leadingZeroBitCountProviderMock,
						CreatedAtModulus:              10 * time.Minute,
						TTL:                           ttl,
						ResourceProvider:              resourceProviderMock,
						MainSerializedPayloadProvider: serializedPayloadProviderMock,
						RandomPayloadByteReader:       iotest.ErrReader(iotest.ErrTimeout),
						RandomPayloadByteCount:        5,
						HashProvider:                  hashProviderMock,
						GenerationHashName:            "SHA-256",
						SecretKey:                     "secret-key",
						SigningHashName:               "SHA-512",
					}
				},
			},
			args: args{
				ctx: context.Background(),
			},
			want: dosProtectorUsecaseModels.SignedChallenge{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				return assert.ErrorIs(test, err, powErrors.ErrIO)
			},
		},
		{
			name: "error/unable to sign the challenge",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(5)
					require.NoError(test, err)

					leadingZeroBitCountProviderMock :=
						dosProtectorUsecasesMocks.NewMockLeadingZeroBitCountProvider(test)
					leadingZeroBitCountProviderMock.EXPECT().
						ProvideLeadingZeroBitCount(context.Background()).
						Return(leadingZeroBitCount, nil)

					ttl, err := powValueTypes.NewTTL(100 * 365 * 24 * time.Hour)
					require.NoError(test, err)

					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
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

					serializedPayloadProviderMock :=
						dosProtectorUsecasesMocks.NewMockSerializedPayloadProvider(test)
					serializedPayloadProviderMock.EXPECT().
						ProvideSerializedPayload(context.Background()).
						Return(powValueTypes.NewSerializedPayload("dummy"), nil)

					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-512").
						Return(powValueTypes.Hash{}, iotest.ErrTimeout)

					return ServerDoSProtectorUsecaseOptions{
						LeadingZeroBitCountProvider:   leadingZeroBitCountProviderMock,
						CreatedAtModulus:              10 * time.Minute,
						TTL:                           ttl,
						ResourceProvider:              resourceProviderMock,
						MainSerializedPayloadProvider: serializedPayloadProviderMock,
						RandomPayloadByteReader:       strings.NewReader("0123456789"),
						RandomPayloadByteCount:        5,
						HashProvider:                  hashProviderMock,
						GenerationHashName:            "SHA-256",
						SecretKey:                     "secret-key",
						SigningHashName:               "SHA-512",
					}
				},
			},
			args: args{
				ctx: context.Background(),
			},
			want:    dosProtectorUsecaseModels.SignedChallenge{},
			wantErr: assert.Error,
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			usecase := ServerDoSProtectorUsecase{
				options: data.fields.options(test),
			}
			got, err := usecase.GenerateSignedChallenge(data.args.ctx)

			assert.Equal(test, data.want, got)
			data.wantErr(test, err)
		})
	}
}

func TestServerDoSProtectorUsecase_VerifySolution(test *testing.T) {
	type fields struct {
		options func(test *testing.T) ServerDoSProtectorUsecaseOptions
	}
	type args struct {
		ctx    context.Context
		params dosProtectorUsecaseModels.VerifySolutionParams
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
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
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

					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ServerDoSProtectorUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.VerifySolutionParams{
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
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
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

					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ServerDoSProtectorUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.VerifySolutionParams{
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
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
					return ServerDoSProtectorUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     dosProtectorUsecasesMocks.NewMockHashProvider(test),
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.VerifySolutionParams{
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
			want: pow.Solution{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				target := dosProtectorUsecaseErrors.ErrInvalidParameters
				return assert.ErrorIs(test, err, target)
			},
		},
		{
			name: "error/unable to construct the `CreatedAt` timestamp",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
					return ServerDoSProtectorUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     dosProtectorUsecasesMocks.NewMockHashProvider(test),
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.VerifySolutionParams{
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
			want: pow.Solution{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				target := dosProtectorUsecaseErrors.ErrInvalidParameters
				return assert.ErrorIs(test, err, target)
			},
		},
		{
			name: "error/unable to parse the TTL",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
					return ServerDoSProtectorUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     dosProtectorUsecasesMocks.NewMockHashProvider(test),
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.VerifySolutionParams{
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
			want: pow.Solution{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				target := dosProtectorUsecaseErrors.ErrInvalidParameters
				return assert.ErrorIs(test, err, target)
			},
		},
		{
			name: "error/unable to get the expected resource",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
					resourceProviderMock.EXPECT().
						ProvideResource(context.Background()).
						Return(powValueTypes.Resource{}, iotest.ErrTimeout)

					return ServerDoSProtectorUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     dosProtectorUsecasesMocks.NewMockHashProvider(test),
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.VerifySolutionParams{
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
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
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

					return ServerDoSProtectorUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     dosProtectorUsecasesMocks.NewMockHashProvider(test),
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.VerifySolutionParams{
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
			want: pow.Solution{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				target := dosProtectorUsecaseErrors.ErrInvalidParameters
				return assert.ErrorIs(test, err, target)
			},
		},
		{
			name: "error/resource doesn't match the expected one",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
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

					return ServerDoSProtectorUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     dosProtectorUsecasesMocks.NewMockHashProvider(test),
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.VerifySolutionParams{
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
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
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

					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.Hash{}, iotest.ErrTimeout)

					return ServerDoSProtectorUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.VerifySolutionParams{
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
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
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

					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ServerDoSProtectorUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.VerifySolutionParams{
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
			want: pow.Solution{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				target := dosProtectorUsecaseErrors.ErrInvalidParameters
				return assert.ErrorIs(test, err, target)
			},
		},
		{
			name: "error/unable to build the challenge",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
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

					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ServerDoSProtectorUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.VerifySolutionParams{
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
			want: pow.Solution{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				target := dosProtectorUsecaseErrors.ErrInvalidParameters
				return assert.ErrorIs(test, err, target)
			},
		},
		{
			name: "error/challenge is outdated",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
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

					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ServerDoSProtectorUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.VerifySolutionParams{
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
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
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

					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ServerDoSProtectorUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.VerifySolutionParams{
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
			want: pow.Solution{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				target := dosProtectorUsecaseErrors.ErrInvalidParameters
				return assert.ErrorIs(test, err, target)
			},
		},
		{
			name: "error/unable to parse the hash sum",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
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

					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ServerDoSProtectorUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.VerifySolutionParams{
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
			want: pow.Solution{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				target := dosProtectorUsecaseErrors.ErrInvalidParameters
				return assert.ErrorIs(test, err, target)
			},
		},
		{
			name: "error/unable to build the solution",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
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

					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ServerDoSProtectorUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.VerifySolutionParams{
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
			want: pow.Solution{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				target := dosProtectorUsecaseErrors.ErrInvalidParameters
				return assert.ErrorIs(test, err, target)
			},
		},
		{
			name: "error/unable to verify the solution",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
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

					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ServerDoSProtectorUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     hashProviderMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.VerifySolutionParams{
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
			usecase := ServerDoSProtectorUsecase{
				options: data.fields.options(test),
			}
			got, err := usecase.VerifySolution(data.args.ctx, data.args.params)

			assert.Equal(test, data.want, got)
			data.wantErr(test, err)
		})
	}
}

func TestServerDoSProtectorUsecase_VerifySolutionAndChallengeSignature(test *testing.T) { //nolint:lll
	type fields struct {
		options func(test *testing.T) ServerDoSProtectorUsecaseOptions
	}
	type args struct {
		ctx    context.Context
		params dosProtectorUsecaseModels.VerifySolutionAndChallengeSignatureParams
	}

	for _, data := range []struct {
		name    string
		fields  fields
		args    args
		want    pow.Solution
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "success",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
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

					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-512").
						Return(powValueTypes.NewHash(sha512.New()), nil)

					return ServerDoSProtectorUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     hashProviderMock,
						SecretKey:        "secret-key",
						SigningHashName:  "SHA-512",
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.VerifySolutionAndChallengeSignatureParams{ //nolint:lll
					VerifySolutionParams: dosProtectorUsecaseModels.VerifySolutionParams{
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
					Signature: "4b4f547d39c52803" +
						"44cac19f32732a5c" +
						"677a1f21763eaedd" +
						"0e21e93934999186" +
						"a62fd71e0578c83d" +
						"b137be9030eea30b" +
						"772c0919cc98fcf9" +
						"f4285b78c2d78ba9",
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
			name: "error/unable to verify the solution/regular error",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
					resourceProviderMock.EXPECT().
						ProvideResource(context.Background()).
						Return(powValueTypes.Resource{}, iotest.ErrTimeout)

					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					return ServerDoSProtectorUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     hashProviderMock,
						SecretKey:        "secret-key",
						SigningHashName:  "SHA-512",
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.VerifySolutionAndChallengeSignatureParams{ //nolint:lll
					VerifySolutionParams: dosProtectorUsecaseModels.VerifySolutionParams{
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
					Signature: "4b4f547d39c52803" +
						"44cac19f32732a5c" +
						"677a1f21763eaedd" +
						"0e21e93934999186" +
						"a62fd71e0578c83d" +
						"b137be9030eea30b" +
						"772c0919cc98fcf9" +
						"f4285b78c2d78ba9",
				},
			},
			want:    pow.Solution{},
			wantErr: assert.Error,
		},
		{
			name: "error/" +
				"unable to verify the solution/" +
				"unable to construct the leading zero bit count",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					return ServerDoSProtectorUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     hashProviderMock,
						SecretKey:        "secret-key",
						SigningHashName:  "SHA-512",
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.VerifySolutionAndChallengeSignatureParams{ //nolint:lll
					VerifySolutionParams: dosProtectorUsecaseModels.VerifySolutionParams{
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
					Signature: "4b4f547d39c52803" +
						"44cac19f32732a5c" +
						"677a1f21763eaedd" +
						"0e21e93934999186" +
						"a62fd71e0578c83d" +
						"b137be9030eea30b" +
						"772c0919cc98fcf9" +
						"f4285b78c2d78ba9",
				},
			},
			want: pow.Solution{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				target := dosProtectorUsecaseErrors.ErrInvalidParameters
				return assert.ErrorIs(test, err, target)
			},
		},
		{
			name: "error/unable to verify the solution/unable to verify the solution",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
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

					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)

					return ServerDoSProtectorUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     hashProviderMock,
						SecretKey:        "secret-key",
						SigningHashName:  "SHA-512",
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.VerifySolutionAndChallengeSignatureParams{ //nolint:lll
					VerifySolutionParams: dosProtectorUsecaseModels.VerifySolutionParams{
						LeadingZeroBitCount: 23,
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
					Signature: "4b4f547d39c52803" +
						"44cac19f32732a5c" +
						"677a1f21763eaedd" +
						"0e21e93934999186" +
						"a62fd71e0578c83d" +
						"b137be9030eea30b" +
						"772c0919cc98fcf9" +
						"f4285b78c2d78ba9",
				},
			},
			want: pow.Solution{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				return assert.ErrorIs(test, err, powErrors.ErrValidationFailure)
			},
		},
		{
			name: "error/unable to sign the challenge",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
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

					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-512").
						Return(powValueTypes.Hash{}, iotest.ErrTimeout)

					return ServerDoSProtectorUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     hashProviderMock,
						SecretKey:        "secret-key",
						SigningHashName:  "SHA-512",
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.VerifySolutionAndChallengeSignatureParams{ //nolint:lll
					VerifySolutionParams: dosProtectorUsecaseModels.VerifySolutionParams{
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
					Signature: "4b4f547d39c52803" +
						"44cac19f32732a5c" +
						"677a1f21763eaedd" +
						"0e21e93934999186" +
						"a62fd71e0578c83d" +
						"b137be9030eea30b" +
						"772c0919cc98fcf9" +
						"f4285b78c2d78ba9",
				},
			},
			want:    pow.Solution{},
			wantErr: assert.Error,
		},
		{
			name: "error/unable to parse the signature",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
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

					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-512").
						Return(powValueTypes.NewHash(sha512.New()), nil)

					return ServerDoSProtectorUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     hashProviderMock,
						SecretKey:        "secret-key",
						SigningHashName:  "SHA-512",
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.VerifySolutionAndChallengeSignatureParams{ //nolint:lll
					VerifySolutionParams: dosProtectorUsecaseModels.VerifySolutionParams{
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
					Signature: "invalid",
				},
			},
			want: pow.Solution{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				target := dosProtectorUsecaseErrors.ErrInvalidParameters
				return assert.ErrorIs(test, err, target)
			},
		},
		{
			name: "error/signature doesn't match the expected one",
			fields: fields{
				options: func(test *testing.T) ServerDoSProtectorUsecaseOptions {
					resourceProviderMock :=
						dosProtectorUsecasesMocks.NewMockResourceProvider(test)
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

					hashProviderMock := dosProtectorUsecasesMocks.NewMockHashProvider(test)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-256").
						Return(powValueTypes.NewHash(sha256.New()), nil)
					hashProviderMock.EXPECT().
						ProvideHashByName(context.Background(), "SHA-512").
						Return(powValueTypes.NewHash(sha512.New()), nil)

					return ServerDoSProtectorUsecaseOptions{
						ResourceProvider: resourceProviderMock,
						HashProvider:     hashProviderMock,
						SecretKey:        "different-secret-key",
						SigningHashName:  "SHA-512",
					}
				},
			},
			args: args{
				ctx: context.Background(),
				params: dosProtectorUsecaseModels.VerifySolutionAndChallengeSignatureParams{ //nolint:lll
					VerifySolutionParams: dosProtectorUsecaseModels.VerifySolutionParams{
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
					Signature: "4b4f547d39c52803" +
						"44cac19f32732a5c" +
						"677a1f21763eaedd" +
						"0e21e93934999186" +
						"a62fd71e0578c83d" +
						"b137be9030eea30b" +
						"772c0919cc98fcf9" +
						"f4285b78c2d78ba9",
				},
			},
			want: pow.Solution{},
			wantErr: func(test assert.TestingT, err error, msgAndArgs ...any) bool {
				return assert.ErrorIs(test, err, powErrors.ErrValidationFailure)
			},
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			usecase := ServerDoSProtectorUsecase{
				options: data.fields.options(test),
			}
			got, err := usecase.VerifySolutionAndChallengeSignature(
				data.args.ctx,
				data.args.params,
			)

			assert.Equal(test, data.want, got)
			data.wantErr(test, err)
		})
	}
}
