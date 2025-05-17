package dosProtectorAdapterClients

import (
	"bytes"
	"context"
	"crypto/sha256"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"testing/iotest"
	"time"

	"github.com/samber/mo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	dosProtectorAdapterModels "github.com/thewizardplusplus/go-dos-protector/adapters/models"
	dosProtectorAdapterClientsMocks "github.com/thewizardplusplus/go-dos-protector/mocks/github.com/thewizardplusplus/go-dos-protector/adapters/clients"
	dosProtectorUsecases "github.com/thewizardplusplus/go-dos-protector/usecases"
	dosProtectorUsecaseModels "github.com/thewizardplusplus/go-dos-protector/usecases/models"
	pow "github.com/thewizardplusplus/go-pow"
	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

func TestHTTPClient_interface(test *testing.T) {
	assert.Implements(test, (*HTTPClient)(nil), &http.Client{})
}

func TestClientDoSProtectorUsecase_interface(test *testing.T) {
	assert.Implements(
		test,
		(*DoSProtectorUsecase)(nil),
		&dosProtectorUsecases.ClientDoSProtectorUsecase{},
	)
}

func TestNewHTTPClientWrapper(test *testing.T) {
	type args struct {
		options func(test *testing.T) HTTPClientWrapperOptions
	}

	for _, data := range []struct {
		name string
		args args
		want func(test *testing.T) HTTPClientWrapper
	}{
		{
			name: "success",
			args: args{
				options: func(test *testing.T) HTTPClientWrapperOptions {
					httpClientMock := dosProtectorAdapterClientsMocks.NewMockHTTPClient(test)
					return HTTPClientWrapperOptions{
						HTTPClient: httpClientMock,
					}
				},
			},
			want: func(test *testing.T) HTTPClientWrapper {
				httpClientMock := dosProtectorAdapterClientsMocks.NewMockHTTPClient(test)
				return HTTPClientWrapper{
					options: HTTPClientWrapperOptions{
						HTTPClient: httpClientMock,
					},
				}
			},
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			got := NewHTTPClientWrapper(data.args.options(test))

			assert.Equal(test, data.want(test), got)
		})
	}
}

func TestHTTPClientWrapper_Do(test *testing.T) {
	type fields struct {
		options func(test *testing.T) HTTPClientWrapperOptions
	}
	type args struct {
		request *http.Request
	}

	for _, data := range []struct {
		name    string
		fields  fields
		args    args
		want    *http.Response
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "success",
			fields: fields{
				options: func(test *testing.T) HTTPClientWrapperOptions {
					headRequest, err := http.NewRequestWithContext(
						context.Background(),
						http.MethodHead,
						"https://example.com/",
						nil,
					)
					require.NoError(test, err)

					mainRequest :=
						httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
					mainRequest.Header.Set(
						dosProtectorAdapterModels.SolutionHeaderKey,
						"created-at=2000-01-02T03%3A04%3A05.000000006Z"+
							"&hash-data-layout="+
							"%7B%7B.Challenge.LeadingZeroBitCount.ToInt%7D%7D"+
							"%3A%7B%7B.Challenge.SerializedPayload.ToString%7D%7D"+
							"%3A%7B%7B.Nonce.ToString%7D%7D"+
							"&hash-name=SHA-256"+
							"&hash-sum="+
							"005d372c56e6c6b5"+
							"2ad4a8325654692e"+
							"c9aa3af5f7302174"+
							"8bc3fdb124ae9b20"+
							"&leading-zero-bit-count=5"+
							"&nonce=37"+
							"&payload=dummy"+
							"&resource=https%3A%2F%2Fexample.com%2F"+
							"&ttl="+(100*365*24*time.Hour).String(),
					)
					mainRequest.Header.Set(
						dosProtectorAdapterModels.SignatureHeaderKey,
						"dummy",
					)

					httpClientMock := dosProtectorAdapterClientsMocks.NewMockHTTPClient(test)
					httpClientMock.EXPECT().
						Do(headRequest).
						Return(
							&http.Response{
								StatusCode: dosProtectorAdapterModels.ResponseStatusToHEADRequest,
								Header: http.Header{
									dosProtectorAdapterModels.ChallengeHeaderKey: {
										"created-at=2000-01-02T03%3A04%3A05.000000006Z" +
											"&hash-data-layout=" +
											"%7B%7B+.Challenge.LeadingZeroBitCount.ToInt+%7D%7D" +
											"%3A%7B%7B+.Challenge.SerializedPayload.ToString+%7D%7D" +
											"%3A%7B%7B+.Nonce.ToString+%7D%7D" +
											"&hash-name=SHA-256" +
											"&leading-zero-bit-count=5" +
											"&payload=dummy" +
											"&resource=https%3A%2F%2Fexample.com%2F" +
											"&ttl=876000h0m0s",
									},
									dosProtectorAdapterModels.SignatureHeaderKey: {
										"dummy",
									},
								},
							},
							nil,
						)
					httpClientMock.EXPECT().
						Do(mainRequest).
						Return(&http.Response{StatusCode: http.StatusOK}, nil)

					leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(5)
					require.NoError(test, err)

					createdAt, err := powValueTypes.NewCreatedAt(
						time.Date(2000, time.January, 2, 3, 4, 5, 6, time.UTC),
					)
					require.NoError(test, err)

					ttl, err := powValueTypes.NewTTL(100 * 365 * 24 * time.Hour)
					require.NoError(test, err)

					hash, err := powValueTypes.NewHashWithName(sha256.New(), "SHA-256")
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
						SetHash(hash).
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

					dosProtectorUsecaseMock :=
						dosProtectorAdapterClientsMocks.NewMockDoSProtectorUsecase(test)
					dosProtectorUsecaseMock.EXPECT().
						SolveChallenge(
							context.Background(),
							dosProtectorUsecaseModels.SolveChallengeParams{
								LeadingZeroBitCount: 5,
								CreatedAt:           "2000-01-02T03:04:05.000000006Z",
								TTL:                 "876000h0m0s",
								Resource:            "https://example.com/",
								Payload:             "dummy",
								HashName:            "SHA-256",
								HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
									":{{ .Challenge.SerializedPayload.ToString }}" +
									":{{ .Nonce.ToString }}",
								MaxAttemptCount: mo.Some(1000),
								RandomInitialNonceParams: mo.Some(powValueTypes.RandomNonceParams{
									RandomReader: bytes.NewReader([]byte("dummy")),
									MinRawValue:  big.NewInt(123),
									MaxRawValue:  big.NewInt(142),
								}),
							},
						).
						Return(solution, nil)

					return HTTPClientWrapperOptions{
						HTTPClient:          httpClientMock,
						DoSProtectorUsecase: dosProtectorUsecaseMock,
						MaxAttemptCount:     mo.Some(1000),
						RandomInitialNonceParams: mo.Some(powValueTypes.RandomNonceParams{
							RandomReader: bytes.NewReader([]byte("dummy")),
							MinRawValue:  big.NewInt(123),
							MaxRawValue:  big.NewInt(142),
						}),
					}
				},
			},
			args: args{
				request: httptest.NewRequest(http.MethodGet, "https://example.com/", nil),
			},
			want:    &http.Response{StatusCode: http.StatusOK},
			wantErr: assert.NoError,
		},
		{
			name: "error/unable to request a new challenge",
			fields: fields{
				options: func(test *testing.T) HTTPClientWrapperOptions {
					headRequest, err := http.NewRequestWithContext(
						context.Background(),
						http.MethodHead,
						"https://example.com/",
						nil,
					)
					require.NoError(test, err)

					httpClientMock := dosProtectorAdapterClientsMocks.NewMockHTTPClient(test)
					httpClientMock.EXPECT().
						Do(headRequest).
						Return(nil, iotest.ErrTimeout)

					dosProtectorUsecaseMock :=
						dosProtectorAdapterClientsMocks.NewMockDoSProtectorUsecase(test)
					return HTTPClientWrapperOptions{
						HTTPClient:          httpClientMock,
						DoSProtectorUsecase: dosProtectorUsecaseMock,
						MaxAttemptCount:     mo.Some(1000),
						RandomInitialNonceParams: mo.Some(powValueTypes.RandomNonceParams{
							RandomReader: bytes.NewReader([]byte("dummy")),
							MinRawValue:  big.NewInt(123),
							MaxRawValue:  big.NewInt(142),
						}),
					}
				},
			},
			args: args{
				request: httptest.NewRequest(http.MethodGet, "https://example.com/", nil),
			},
			want:    nil,
			wantErr: assert.Error,
		},
		{
			name: "error/unable to solve the challenge",
			fields: fields{
				options: func(test *testing.T) HTTPClientWrapperOptions {
					headRequest, err := http.NewRequestWithContext(
						context.Background(),
						http.MethodHead,
						"https://example.com/",
						nil,
					)
					require.NoError(test, err)

					httpClientMock := dosProtectorAdapterClientsMocks.NewMockHTTPClient(test)
					httpClientMock.EXPECT().
						Do(headRequest).
						Return(
							&http.Response{
								StatusCode: dosProtectorAdapterModels.ResponseStatusToHEADRequest,
								Header: http.Header{
									dosProtectorAdapterModels.ChallengeHeaderKey: {
										"created-at=2000-01-02T03%3A04%3A05.000000006Z" +
											"&hash-data-layout=" +
											"%7B%7B+.Challenge.LeadingZeroBitCount.ToInt+%7D%7D" +
											"%3A%7B%7B+.Challenge.SerializedPayload.ToString+%7D%7D" +
											"%3A%7B%7B+.Nonce.ToString+%7D%7D" +
											"&hash-name=SHA-256" +
											"&leading-zero-bit-count=5" +
											"&payload=dummy" +
											"&resource=https%3A%2F%2Fexample.com%2F" +
											"&ttl=876000h0m0s",
									},
									dosProtectorAdapterModels.SignatureHeaderKey: {
										"dummy",
									},
								},
							},
							nil,
						)

					dosProtectorUsecaseMock :=
						dosProtectorAdapterClientsMocks.NewMockDoSProtectorUsecase(test)
					dosProtectorUsecaseMock.EXPECT().
						SolveChallenge(
							context.Background(),
							dosProtectorUsecaseModels.SolveChallengeParams{
								LeadingZeroBitCount: 5,
								CreatedAt:           "2000-01-02T03:04:05.000000006Z",
								TTL:                 "876000h0m0s",
								Resource:            "https://example.com/",
								Payload:             "dummy",
								HashName:            "SHA-256",
								HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
									":{{ .Challenge.SerializedPayload.ToString }}" +
									":{{ .Nonce.ToString }}",
								MaxAttemptCount: mo.Some(1000),
								RandomInitialNonceParams: mo.Some(powValueTypes.RandomNonceParams{
									RandomReader: bytes.NewReader([]byte("dummy")),
									MinRawValue:  big.NewInt(123),
									MaxRawValue:  big.NewInt(142),
								}),
							},
						).
						Return(pow.Solution{}, iotest.ErrTimeout)

					return HTTPClientWrapperOptions{
						HTTPClient:          httpClientMock,
						DoSProtectorUsecase: dosProtectorUsecaseMock,
						MaxAttemptCount:     mo.Some(1000),
						RandomInitialNonceParams: mo.Some(powValueTypes.RandomNonceParams{
							RandomReader: bytes.NewReader([]byte("dummy")),
							MinRawValue:  big.NewInt(123),
							MaxRawValue:  big.NewInt(142),
						}),
					}
				},
			},
			args: args{
				request: httptest.NewRequest(http.MethodGet, "https://example.com/", nil),
			},
			want:    nil,
			wantErr: assert.Error,
		},
		{
			name: "error/unable to construct the solution model",
			fields: fields{
				options: func(test *testing.T) HTTPClientWrapperOptions {
					headRequest, err := http.NewRequestWithContext(
						context.Background(),
						http.MethodHead,
						"https://example.com/",
						nil,
					)
					require.NoError(test, err)

					httpClientMock := dosProtectorAdapterClientsMocks.NewMockHTTPClient(test)
					httpClientMock.EXPECT().
						Do(headRequest).
						Return(
							&http.Response{
								StatusCode: dosProtectorAdapterModels.ResponseStatusToHEADRequest,
								Header: http.Header{
									dosProtectorAdapterModels.ChallengeHeaderKey: {
										"created-at=2000-01-02T03%3A04%3A05.000000006Z" +
											"&hash-data-layout=" +
											"%7B%7B+.Challenge.LeadingZeroBitCount.ToInt+%7D%7D" +
											"%3A%7B%7B+.Challenge.SerializedPayload.ToString+%7D%7D" +
											"%3A%7B%7B+.Nonce.ToString+%7D%7D" +
											"&hash-name=SHA-256" +
											"&leading-zero-bit-count=5" +
											"&payload=dummy" +
											"&resource=https%3A%2F%2Fexample.com%2F" +
											"&ttl=876000h0m0s",
									},
									dosProtectorAdapterModels.SignatureHeaderKey: {
										"dummy",
									},
								},
							},
							nil,
						)

					leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(5)
					require.NoError(test, err)

					hash, err := powValueTypes.NewHashWithName(sha256.New(), "SHA-256")
					require.NoError(test, err)

					challenge, err := pow.NewChallengeBuilder().
						SetLeadingZeroBitCount(leadingZeroBitCount).
						SetResource(powValueTypes.NewResource(&url.URL{
							Scheme: "https",
							Host:   "example.com",
							Path:   "/",
						})).
						SetSerializedPayload(powValueTypes.NewSerializedPayload("dummy")).
						SetHash(hash).
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

					dosProtectorUsecaseMock :=
						dosProtectorAdapterClientsMocks.NewMockDoSProtectorUsecase(test)
					dosProtectorUsecaseMock.EXPECT().
						SolveChallenge(
							context.Background(),
							dosProtectorUsecaseModels.SolveChallengeParams{
								LeadingZeroBitCount: 5,
								CreatedAt:           "2000-01-02T03:04:05.000000006Z",
								TTL:                 "876000h0m0s",
								Resource:            "https://example.com/",
								Payload:             "dummy",
								HashName:            "SHA-256",
								HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
									":{{ .Challenge.SerializedPayload.ToString }}" +
									":{{ .Nonce.ToString }}",
								MaxAttemptCount: mo.Some(1000),
								RandomInitialNonceParams: mo.Some(powValueTypes.RandomNonceParams{
									RandomReader: bytes.NewReader([]byte("dummy")),
									MinRawValue:  big.NewInt(123),
									MaxRawValue:  big.NewInt(142),
								}),
							},
						).
						Return(solution, nil)

					return HTTPClientWrapperOptions{
						HTTPClient:          httpClientMock,
						DoSProtectorUsecase: dosProtectorUsecaseMock,
						MaxAttemptCount:     mo.Some(1000),
						RandomInitialNonceParams: mo.Some(powValueTypes.RandomNonceParams{
							RandomReader: bytes.NewReader([]byte("dummy")),
							MinRawValue:  big.NewInt(123),
							MaxRawValue:  big.NewInt(142),
						}),
					}
				},
			},
			args: args{
				request: httptest.NewRequest(http.MethodGet, "https://example.com/", nil),
			},
			want:    nil,
			wantErr: assert.Error,
		},
		{
			name: "error/unable to send the main request",
			fields: fields{
				options: func(test *testing.T) HTTPClientWrapperOptions {
					headRequest, err := http.NewRequestWithContext(
						context.Background(),
						http.MethodHead,
						"https://example.com/",
						nil,
					)
					require.NoError(test, err)

					mainRequest :=
						httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
					mainRequest.Header.Set(
						dosProtectorAdapterModels.SolutionHeaderKey,
						"created-at=2000-01-02T03%3A04%3A05.000000006Z"+
							"&hash-data-layout="+
							"%7B%7B.Challenge.LeadingZeroBitCount.ToInt%7D%7D"+
							"%3A%7B%7B.Challenge.SerializedPayload.ToString%7D%7D"+
							"%3A%7B%7B.Nonce.ToString%7D%7D"+
							"&hash-name=SHA-256"+
							"&hash-sum="+
							"005d372c56e6c6b5"+
							"2ad4a8325654692e"+
							"c9aa3af5f7302174"+
							"8bc3fdb124ae9b20"+
							"&leading-zero-bit-count=5"+
							"&nonce=37"+
							"&payload=dummy"+
							"&resource=https%3A%2F%2Fexample.com%2F"+
							"&ttl="+(100*365*24*time.Hour).String(),
					)
					mainRequest.Header.Set(
						dosProtectorAdapterModels.SignatureHeaderKey,
						"dummy",
					)

					httpClientMock := dosProtectorAdapterClientsMocks.NewMockHTTPClient(test)
					httpClientMock.EXPECT().
						Do(headRequest).
						Return(
							&http.Response{
								StatusCode: dosProtectorAdapterModels.ResponseStatusToHEADRequest,
								Header: http.Header{
									dosProtectorAdapterModels.ChallengeHeaderKey: {
										"created-at=2000-01-02T03%3A04%3A05.000000006Z" +
											"&hash-data-layout=" +
											"%7B%7B+.Challenge.LeadingZeroBitCount.ToInt+%7D%7D" +
											"%3A%7B%7B+.Challenge.SerializedPayload.ToString+%7D%7D" +
											"%3A%7B%7B+.Nonce.ToString+%7D%7D" +
											"&hash-name=SHA-256" +
											"&leading-zero-bit-count=5" +
											"&payload=dummy" +
											"&resource=https%3A%2F%2Fexample.com%2F" +
											"&ttl=876000h0m0s",
									},
									dosProtectorAdapterModels.SignatureHeaderKey: {
										"dummy",
									},
								},
							},
							nil,
						)
					httpClientMock.EXPECT().
						Do(mainRequest).
						Return(nil, iotest.ErrTimeout)

					leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(5)
					require.NoError(test, err)

					createdAt, err := powValueTypes.NewCreatedAt(
						time.Date(2000, time.January, 2, 3, 4, 5, 6, time.UTC),
					)
					require.NoError(test, err)

					ttl, err := powValueTypes.NewTTL(100 * 365 * 24 * time.Hour)
					require.NoError(test, err)

					hash, err := powValueTypes.NewHashWithName(sha256.New(), "SHA-256")
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
						SetHash(hash).
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

					dosProtectorUsecaseMock :=
						dosProtectorAdapterClientsMocks.NewMockDoSProtectorUsecase(test)
					dosProtectorUsecaseMock.EXPECT().
						SolveChallenge(
							context.Background(),
							dosProtectorUsecaseModels.SolveChallengeParams{
								LeadingZeroBitCount: 5,
								CreatedAt:           "2000-01-02T03:04:05.000000006Z",
								TTL:                 "876000h0m0s",
								Resource:            "https://example.com/",
								Payload:             "dummy",
								HashName:            "SHA-256",
								HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
									":{{ .Challenge.SerializedPayload.ToString }}" +
									":{{ .Nonce.ToString }}",
								MaxAttemptCount: mo.Some(1000),
								RandomInitialNonceParams: mo.Some(powValueTypes.RandomNonceParams{
									RandomReader: bytes.NewReader([]byte("dummy")),
									MinRawValue:  big.NewInt(123),
									MaxRawValue:  big.NewInt(142),
								}),
							},
						).
						Return(solution, nil)

					return HTTPClientWrapperOptions{
						HTTPClient:          httpClientMock,
						DoSProtectorUsecase: dosProtectorUsecaseMock,
						MaxAttemptCount:     mo.Some(1000),
						RandomInitialNonceParams: mo.Some(powValueTypes.RandomNonceParams{
							RandomReader: bytes.NewReader([]byte("dummy")),
							MinRawValue:  big.NewInt(123),
							MaxRawValue:  big.NewInt(142),
						}),
					}
				},
			},
			args: args{
				request: httptest.NewRequest(http.MethodGet, "https://example.com/", nil),
			},
			want:    nil,
			wantErr: assert.Error,
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			originalRequest := data.args.request.Clone(context.Background())

			wrapper := HTTPClientWrapper{
				options: data.fields.options(test),
			}
			got, err := wrapper.Do(data.args.request)

			assert.Equal(test, data.want, got)
			data.wantErr(test, err)
			assert.Equal(test, originalRequest, data.args.request)
		})
	}
}

func TestHTTPClientWrapper_requestChallenge(test *testing.T) {
	type fields struct {
		options func(test *testing.T) HTTPClientWrapperOptions
	}
	type args struct {
		ctx context.Context
		url string
	}

	for _, data := range []struct {
		name    string
		fields  fields
		args    args
		want    dosProtectorAdapterModels.SignedChallenge
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "success",
			fields: fields{
				options: func(test *testing.T) HTTPClientWrapperOptions {
					request, err := http.NewRequestWithContext(
						context.Background(),
						http.MethodHead,
						"https://example.com/",
						nil,
					)
					require.NoError(test, err)

					httpClientMock := dosProtectorAdapterClientsMocks.NewMockHTTPClient(test)
					httpClientMock.EXPECT().
						Do(request).
						Return(
							&http.Response{
								StatusCode: dosProtectorAdapterModels.ResponseStatusToHEADRequest,
								Header: http.Header{
									dosProtectorAdapterModels.ChallengeHeaderKey: {
										"created-at=2000-01-02T03%3A04%3A05.000000006Z" +
											"&hash-data-layout=" +
											"%7B%7B+.Challenge.LeadingZeroBitCount.ToInt+%7D%7D" +
											"%3A%7B%7B+.Challenge.SerializedPayload.ToString+%7D%7D" +
											"%3A%7B%7B+.Nonce.ToString+%7D%7D" +
											"&hash-name=SHA-256" +
											"&leading-zero-bit-count=5" +
											"&payload=dummy" +
											"&resource=https%3A%2F%2Fexample.com%2F" +
											"&ttl=876000h0m0s",
									},
									dosProtectorAdapterModels.SignatureHeaderKey: {
										"dummy",
									},
								},
							},
							nil,
						)

					return HTTPClientWrapperOptions{
						HTTPClient: httpClientMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				url: "https://example.com/",
			},
			want: dosProtectorAdapterModels.SignedChallenge{
				Challenge: dosProtectorAdapterModels.Challenge{
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

				Signature: "dummy",
			},
			wantErr: assert.NoError,
		},
		{
			name: "error/unable to construct a new HEAD request",
			fields: fields{
				options: func(test *testing.T) HTTPClientWrapperOptions {
					httpClientMock := dosProtectorAdapterClientsMocks.NewMockHTTPClient(test)
					return HTTPClientWrapperOptions{
						HTTPClient: httpClientMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				url: ":",
			},
			want:    dosProtectorAdapterModels.SignedChallenge{},
			wantErr: assert.Error,
		},
		{
			name: "error/unable to send the HEAD request",
			fields: fields{
				options: func(test *testing.T) HTTPClientWrapperOptions {
					request, err := http.NewRequestWithContext(
						context.Background(),
						http.MethodHead,
						"https://example.com/",
						nil,
					)
					require.NoError(test, err)

					httpClientMock := dosProtectorAdapterClientsMocks.NewMockHTTPClient(test)
					httpClientMock.EXPECT().
						Do(request).
						Return(nil, iotest.ErrTimeout)

					return HTTPClientWrapperOptions{
						HTTPClient: httpClientMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				url: "https://example.com/",
			},
			want:    dosProtectorAdapterModels.SignedChallenge{},
			wantErr: assert.Error,
		},
		{
			name: "error/unexpected status of the response to the HEAD request",
			fields: fields{
				options: func(test *testing.T) HTTPClientWrapperOptions {
					request, err := http.NewRequestWithContext(
						context.Background(),
						http.MethodHead,
						"https://example.com/",
						nil,
					)
					require.NoError(test, err)

					httpClientMock := dosProtectorAdapterClientsMocks.NewMockHTTPClient(test)
					httpClientMock.EXPECT().
						Do(request).
						Return(&http.Response{StatusCode: http.StatusOK}, nil)

					return HTTPClientWrapperOptions{
						HTTPClient: httpClientMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				url: "https://example.com/",
			},
			want:    dosProtectorAdapterModels.SignedChallenge{},
			wantErr: assert.Error,
		},
		{
			name: "error/challenge header is required",
			fields: fields{
				options: func(test *testing.T) HTTPClientWrapperOptions {
					request, err := http.NewRequestWithContext(
						context.Background(),
						http.MethodHead,
						"https://example.com/",
						nil,
					)
					require.NoError(test, err)

					httpClientMock := dosProtectorAdapterClientsMocks.NewMockHTTPClient(test)
					httpClientMock.EXPECT().
						Do(request).
						Return(
							&http.Response{
								StatusCode: dosProtectorAdapterModels.ResponseStatusToHEADRequest,
							},
							nil,
						)

					return HTTPClientWrapperOptions{
						HTTPClient: httpClientMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				url: "https://example.com/",
			},
			want:    dosProtectorAdapterModels.SignedChallenge{},
			wantErr: assert.Error,
		},
		{
			name: "error/unable to parse the challenge model",
			fields: fields{
				options: func(test *testing.T) HTTPClientWrapperOptions {
					request, err := http.NewRequestWithContext(
						context.Background(),
						http.MethodHead,
						"https://example.com/",
						nil,
					)
					require.NoError(test, err)

					httpClientMock := dosProtectorAdapterClientsMocks.NewMockHTTPClient(test)
					httpClientMock.EXPECT().
						Do(request).
						Return(
							&http.Response{
								StatusCode: dosProtectorAdapterModels.ResponseStatusToHEADRequest,
								Header: http.Header{
									dosProtectorAdapterModels.ChallengeHeaderKey: {
										"leading-zero-bit-count=invalid",
									},
								},
							},
							nil,
						)

					return HTTPClientWrapperOptions{
						HTTPClient: httpClientMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				url: "https://example.com/",
			},
			want:    dosProtectorAdapterModels.SignedChallenge{},
			wantErr: assert.Error,
		},
		{
			name: "error/signature header is required",
			fields: fields{
				options: func(test *testing.T) HTTPClientWrapperOptions {
					request, err := http.NewRequestWithContext(
						context.Background(),
						http.MethodHead,
						"https://example.com/",
						nil,
					)
					require.NoError(test, err)

					httpClientMock := dosProtectorAdapterClientsMocks.NewMockHTTPClient(test)
					httpClientMock.EXPECT().
						Do(request).
						Return(
							&http.Response{
								StatusCode: dosProtectorAdapterModels.ResponseStatusToHEADRequest,
								Header: http.Header{
									dosProtectorAdapterModels.ChallengeHeaderKey: {
										"created-at=2000-01-02T03%3A04%3A05.000000006Z" +
											"&hash-data-layout=" +
											"%7B%7B+.Challenge.LeadingZeroBitCount.ToInt+%7D%7D" +
											"%3A%7B%7B+.Challenge.SerializedPayload.ToString+%7D%7D" +
											"%3A%7B%7B+.Nonce.ToString+%7D%7D" +
											"&hash-name=SHA-256" +
											"&leading-zero-bit-count=5" +
											"&payload=dummy" +
											"&resource=https%3A%2F%2Fexample.com%2F" +
											"&ttl=876000h0m0s",
									},
								},
							},
							nil,
						)

					return HTTPClientWrapperOptions{
						HTTPClient: httpClientMock,
					}
				},
			},
			args: args{
				ctx: context.Background(),
				url: "https://example.com/",
			},
			want:    dosProtectorAdapterModels.SignedChallenge{},
			wantErr: assert.Error,
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			wrapper := HTTPClientWrapper{
				options: data.fields.options(test),
			}
			got, err := wrapper.requestChallenge(data.args.ctx, data.args.url)

			assert.Equal(test, data.want, got)
			data.wantErr(test, err)
		})
	}
}
