package dosProtectorAdapterMiddlewares

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"testing/iotest"
	"time"

	"github.com/samber/mo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	dosProtectorAdapterModels "github.com/thewizardplusplus/go-dos-protector/adapters/models"
	dosProtectorAdapterMiddlewaresMocks "github.com/thewizardplusplus/go-dos-protector/mocks/github.com/thewizardplusplus/go-dos-protector/adapters/middlewares"
	dosProtectorUsecases "github.com/thewizardplusplus/go-dos-protector/usecases"
	dosProtectorUsecaseErrors "github.com/thewizardplusplus/go-dos-protector/usecases/errors"
	dosProtectorUsecaseModels "github.com/thewizardplusplus/go-dos-protector/usecases/models"
	pow "github.com/thewizardplusplus/go-pow"
	powErrors "github.com/thewizardplusplus/go-pow/errors"
	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

func TestServerDoSProtectorUsecase_interface(test *testing.T) {
	assert.Implements(
		test,
		(*DoSProtectorUsecase)(nil),
		&dosProtectorUsecases.ServerDoSProtectorUsecase{},
	)
}

func TestHTTPErrorHandler(test *testing.T) {
	assert.True(
		test,
		reflect.TypeOf(http.Error).ConvertibleTo(reflect.TypeFor[HTTPErrorHandler]()),
	)
}

func TestNewDoSProtectorMiddleware(test *testing.T) {
	type args struct {
		options func(test *testing.T) DoSProtectorMiddlewareOptions
	}

	for _, data := range []struct {
		name string
		args args
		want func(test *testing.T, got DoSProtectorMiddleware)
	}{
		{
			name: "success",
			args: args{
				options: func(test *testing.T) DoSProtectorMiddlewareOptions {
					doSProtectorUsecaseMock :=
						dosProtectorAdapterMiddlewaresMocks.NewMockDoSProtectorUsecase(test)
					httpErrorHandlerMock :=
						dosProtectorAdapterMiddlewaresMocks.NewMockhttpErrorHandler(test)
					return DoSProtectorMiddlewareOptions{
						DoSProtectorUsecase: doSProtectorUsecaseMock,
						HTTPErrorHandler:    httpErrorHandlerMock.HandleHTTPError,
					}
				},
			},
			want: func(test *testing.T, got DoSProtectorMiddleware) {
				doSProtectorUsecaseMock :=
					dosProtectorAdapterMiddlewaresMocks.NewMockDoSProtectorUsecase(test)
				assert.Equal(test, doSProtectorUsecaseMock, got.options.DoSProtectorUsecase)
				assert.NotNil(test, got.options.HTTPErrorHandler)
			},
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			got := NewDoSProtectorMiddleware(data.args.options(test))

			data.want(test, got)
		})
	}
}

func TestDoSProtectorMiddleware_ApplyTo(test *testing.T) {
	type fields struct {
		options func(test *testing.T) DoSProtectorMiddlewareOptions
	}
	type args struct {
		handler func(test *testing.T, request *http.Request) http.Handler
	}
	type handlerArgs struct {
		request *http.Request
	}

	for _, data := range []struct {
		name         string
		fields       fields
		args         args
		handlerArgs  handlerArgs
		wantResponse mo.Option[*http.Response]
	}{
		{
			name: "success/without a solution header",
			fields: fields{
				options: func(test *testing.T) DoSProtectorMiddlewareOptions {
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

					doSProtectorUsecaseMock :=
						dosProtectorAdapterMiddlewaresMocks.NewMockDoSProtectorUsecase(test)
					doSProtectorUsecaseMock.EXPECT().
						GenerateSignedChallenge(context.Background()).
						Return(
							dosProtectorUsecaseModels.SignedChallenge{
								Challenge: challenge,
								Signature: "dummy",
							},
							nil,
						)

					httpErrorHandlerMock :=
						dosProtectorAdapterMiddlewaresMocks.NewMockhttpErrorHandler(test)
					return DoSProtectorMiddlewareOptions{
						DoSProtectorUsecase: doSProtectorUsecaseMock,
						HTTPErrorHandler:    httpErrorHandlerMock.HandleHTTPError,
					}
				},
			},
			args: args{
				handler: func(test *testing.T, request *http.Request) http.Handler {
					return dosProtectorAdapterMiddlewaresMocks.NewMockhttpHandler(test)
				},
			},
			handlerArgs: handlerArgs{
				request: httptest.NewRequest(http.MethodGet, "https://example.com/", nil),
			},
			wantResponse: mo.Some(&http.Response{
				Status: fmt.Sprintf(
					"%d %s",
					http.StatusForbidden,
					http.StatusText(http.StatusForbidden),
				),
				StatusCode: http.StatusForbidden,
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header: http.Header{
					dosProtectorAdapterModels.ChallengeHeaderKey: {
						"created-at=2000-01-02T03%3A04%3A05.000000006Z" +
							"&hash-data-layout=" +
							"%7B%7B.Challenge.LeadingZeroBitCount.ToInt%7D%7D" +
							"%3A%7B%7B.Challenge.SerializedPayload.ToString%7D%7D" +
							"%3A%7B%7B.Nonce.ToString%7D%7D" +
							"&hash-name=SHA-256" +
							"&leading-zero-bit-count=5" +
							"&payload=dummy" +
							"&resource=https%3A%2F%2Fexample.com%2F" +
							"&ttl=" + (100 * 365 * 24 * time.Hour).String(),
					},
					dosProtectorAdapterModels.SignatureHeaderKey: {
						"dummy",
					},
				},
				Body:          io.NopCloser(bytes.NewReader(nil)),
				ContentLength: -1,
			}),
		},
		{
			name: "success/with a solution header",
			fields: fields{
				options: func(test *testing.T) DoSProtectorMiddlewareOptions {
					doSProtectorUsecaseMock :=
						dosProtectorAdapterMiddlewaresMocks.NewMockDoSProtectorUsecase(test)
					doSProtectorUsecaseMock.EXPECT().
						VerifySolutionAndChallengeSignature(
							context.Background(),
							dosProtectorUsecaseModels.VerifySolutionAndChallengeSignatureParams{
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
									Nonce: "37",
									HashSum: mo.Some(
										"005d372c56e6c6b5" +
											"2ad4a8325654692e" +
											"c9aa3af5f7302174" +
											"8bc3fdb124ae9b20",
									),
								},

								Signature: "dummy",
							},
						).
						Return(pow.Solution{}, nil)

					httpErrorHandlerMock :=
						dosProtectorAdapterMiddlewaresMocks.NewMockhttpErrorHandler(test)
					return DoSProtectorMiddlewareOptions{
						DoSProtectorUsecase: doSProtectorUsecaseMock,
						HTTPErrorHandler:    httpErrorHandlerMock.HandleHTTPError,
					}
				},
			},
			args: args{
				handler: func(test *testing.T, request *http.Request) http.Handler {
					handlerMock := dosProtectorAdapterMiddlewaresMocks.NewMockhttpHandler(test)
					handlerMock.EXPECT().
						ServeHTTP(mock.AnythingOfType("*httptest.ResponseRecorder"), request)

					return handlerMock
				},
			},
			handlerArgs: handlerArgs{
				request: func() *http.Request {
					request := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
					request.Header.Set(
						dosProtectorAdapterModels.SolutionHeaderKey,
						"created-at=2000-01-02T03%3A04%3A05.000000006Z"+
							"&hash-data-layout="+
							"%7B%7B+.Challenge.LeadingZeroBitCount.ToInt+%7D%7D"+
							"%3A%7B%7B+.Challenge.SerializedPayload.ToString+%7D%7D"+
							"%3A%7B%7B+.Nonce.ToString+%7D%7D"+
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
					request.Header.Set(dosProtectorAdapterModels.SignatureHeaderKey, "dummy")

					return request
				}(),
			},
			wantResponse: mo.None[*http.Response](),
		},
		{
			name: "error" +
				"/without a solution header" +
				"/unable to generate a new signed challenge",
			fields: fields{
				options: func(test *testing.T) DoSProtectorMiddlewareOptions {
					doSProtectorUsecaseMock :=
						dosProtectorAdapterMiddlewaresMocks.NewMockDoSProtectorUsecase(test)
					doSProtectorUsecaseMock.EXPECT().
						GenerateSignedChallenge(context.Background()).
						Return(dosProtectorUsecaseModels.SignedChallenge{}, iotest.ErrTimeout)

					httpErrorHandlerMock :=
						dosProtectorAdapterMiddlewaresMocks.NewMockhttpErrorHandler(test)
					httpErrorHandlerMock.EXPECT().
						HandleHTTPError(
							mock.AnythingOfType("*httptest.ResponseRecorder"),
							mock.AnythingOfType("string"),
							http.StatusInternalServerError,
						)

					return DoSProtectorMiddlewareOptions{
						DoSProtectorUsecase: doSProtectorUsecaseMock,
						HTTPErrorHandler:    httpErrorHandlerMock.HandleHTTPError,
					}
				},
			},
			args: args{
				handler: func(test *testing.T, request *http.Request) http.Handler {
					return dosProtectorAdapterMiddlewaresMocks.NewMockhttpHandler(test)
				},
			},
			handlerArgs: handlerArgs{
				request: httptest.NewRequest(http.MethodGet, "https://example.com/", nil),
			},
			wantResponse: mo.None[*http.Response](),
		},
		{
			name: "error" +
				"/without a solution header" +
				"/unable to construct the challenge model",
			fields: fields{
				options: func(test *testing.T) DoSProtectorMiddlewareOptions {
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

					doSProtectorUsecaseMock :=
						dosProtectorAdapterMiddlewaresMocks.NewMockDoSProtectorUsecase(test)
					doSProtectorUsecaseMock.EXPECT().
						GenerateSignedChallenge(context.Background()).
						Return(
							dosProtectorUsecaseModels.SignedChallenge{
								Challenge: challenge,
								Signature: "dummy",
							},
							nil,
						)

					httpErrorHandlerMock :=
						dosProtectorAdapterMiddlewaresMocks.NewMockhttpErrorHandler(test)
					httpErrorHandlerMock.EXPECT().
						HandleHTTPError(
							mock.AnythingOfType("*httptest.ResponseRecorder"),
							mock.AnythingOfType("string"),
							http.StatusInternalServerError,
						)

					return DoSProtectorMiddlewareOptions{
						DoSProtectorUsecase: doSProtectorUsecaseMock,
						HTTPErrorHandler:    httpErrorHandlerMock.HandleHTTPError,
					}
				},
			},
			args: args{
				handler: func(test *testing.T, request *http.Request) http.Handler {
					return dosProtectorAdapterMiddlewaresMocks.NewMockhttpHandler(test)
				},
			},
			handlerArgs: handlerArgs{
				request: httptest.NewRequest(http.MethodGet, "https://example.com/", nil),
			},
			wantResponse: mo.None[*http.Response](),
		},
		{
			name: "error/with a solution header/unable to parse the solution model",
			fields: fields{
				options: func(test *testing.T) DoSProtectorMiddlewareOptions {
					doSProtectorUsecaseMock :=
						dosProtectorAdapterMiddlewaresMocks.NewMockDoSProtectorUsecase(test)

					httpErrorHandlerMock :=
						dosProtectorAdapterMiddlewaresMocks.NewMockhttpErrorHandler(test)
					httpErrorHandlerMock.EXPECT().
						HandleHTTPError(
							mock.AnythingOfType("*httptest.ResponseRecorder"),
							mock.AnythingOfType("string"),
							http.StatusBadRequest,
						)

					return DoSProtectorMiddlewareOptions{
						DoSProtectorUsecase: doSProtectorUsecaseMock,
						HTTPErrorHandler:    httpErrorHandlerMock.HandleHTTPError,
					}
				},
			},
			args: args{
				handler: func(test *testing.T, request *http.Request) http.Handler {
					return dosProtectorAdapterMiddlewaresMocks.NewMockhttpHandler(test)
				},
			},
			handlerArgs: handlerArgs{
				request: func() *http.Request {
					request := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
					request.Header.Set(
						dosProtectorAdapterModels.SolutionHeaderKey,
						"leading-zero-bit-count=invalid",
					)

					return request
				}(),
			},
			wantResponse: mo.None[*http.Response](),
		},
		{
			name: "error/with a solution header/signature header is required",
			fields: fields{
				options: func(test *testing.T) DoSProtectorMiddlewareOptions {
					doSProtectorUsecaseMock :=
						dosProtectorAdapterMiddlewaresMocks.NewMockDoSProtectorUsecase(test)

					httpErrorHandlerMock :=
						dosProtectorAdapterMiddlewaresMocks.NewMockhttpErrorHandler(test)
					httpErrorHandlerMock.EXPECT().
						HandleHTTPError(
							mock.AnythingOfType("*httptest.ResponseRecorder"),
							mock.AnythingOfType("string"),
							http.StatusBadRequest,
						)

					return DoSProtectorMiddlewareOptions{
						DoSProtectorUsecase: doSProtectorUsecaseMock,
						HTTPErrorHandler:    httpErrorHandlerMock.HandleHTTPError,
					}
				},
			},
			args: args{
				handler: func(test *testing.T, request *http.Request) http.Handler {
					return dosProtectorAdapterMiddlewaresMocks.NewMockhttpHandler(test)
				},
			},
			handlerArgs: handlerArgs{
				request: func() *http.Request {
					request := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
					request.Header.Set(
						dosProtectorAdapterModels.SolutionHeaderKey,
						"created-at=2000-01-02T03%3A04%3A05.000000006Z"+
							"&hash-data-layout="+
							"%7B%7B+.Challenge.LeadingZeroBitCount.ToInt+%7D%7D"+
							"%3A%7B%7B+.Challenge.SerializedPayload.ToString+%7D%7D"+
							"%3A%7B%7B+.Nonce.ToString+%7D%7D"+
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

					return request
				}(),
			},
			wantResponse: mo.None[*http.Response](),
		},
		{
			name: "error" +
				"/with a solution header" +
				"/unable to verify the solution and challenge signature" +
				"/regular error",
			fields: fields{
				options: func(test *testing.T) DoSProtectorMiddlewareOptions {
					doSProtectorUsecaseMock :=
						dosProtectorAdapterMiddlewaresMocks.NewMockDoSProtectorUsecase(test)
					doSProtectorUsecaseMock.EXPECT().
						VerifySolutionAndChallengeSignature(
							context.Background(),
							dosProtectorUsecaseModels.VerifySolutionAndChallengeSignatureParams{
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
									Nonce: "37",
									HashSum: mo.Some(
										"005d372c56e6c6b5" +
											"2ad4a8325654692e" +
											"c9aa3af5f7302174" +
											"8bc3fdb124ae9b20",
									),
								},

								Signature: "dummy",
							},
						).
						Return(pow.Solution{}, iotest.ErrTimeout)

					httpErrorHandlerMock :=
						dosProtectorAdapterMiddlewaresMocks.NewMockhttpErrorHandler(test)
					httpErrorHandlerMock.EXPECT().
						HandleHTTPError(
							mock.AnythingOfType("*httptest.ResponseRecorder"),
							mock.AnythingOfType("string"),
							http.StatusInternalServerError,
						)

					return DoSProtectorMiddlewareOptions{
						DoSProtectorUsecase: doSProtectorUsecaseMock,
						HTTPErrorHandler:    httpErrorHandlerMock.HandleHTTPError,
					}
				},
			},
			args: args{
				handler: func(test *testing.T, request *http.Request) http.Handler {
					return dosProtectorAdapterMiddlewaresMocks.NewMockhttpHandler(test)
				},
			},
			handlerArgs: handlerArgs{
				request: func() *http.Request {
					request := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
					request.Header.Set(
						dosProtectorAdapterModels.SolutionHeaderKey,
						"created-at=2000-01-02T03%3A04%3A05.000000006Z"+
							"&hash-data-layout="+
							"%7B%7B+.Challenge.LeadingZeroBitCount.ToInt+%7D%7D"+
							"%3A%7B%7B+.Challenge.SerializedPayload.ToString+%7D%7D"+
							"%3A%7B%7B+.Nonce.ToString+%7D%7D"+
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
					request.Header.Set(dosProtectorAdapterModels.SignatureHeaderKey, "dummy")

					return request
				}(),
			},
			wantResponse: mo.None[*http.Response](),
		},
		{
			name: "error" +
				"/with a solution header" +
				"/unable to verify the solution and challenge signature" +
				"/invalid parameters",
			fields: fields{
				options: func(test *testing.T) DoSProtectorMiddlewareOptions {
					doSProtectorUsecaseMock :=
						dosProtectorAdapterMiddlewaresMocks.NewMockDoSProtectorUsecase(test)
					doSProtectorUsecaseMock.EXPECT().
						VerifySolutionAndChallengeSignature(
							context.Background(),
							dosProtectorUsecaseModels.VerifySolutionAndChallengeSignatureParams{
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
									Nonce: "37",
									HashSum: mo.Some(
										"005d372c56e6c6b5" +
											"2ad4a8325654692e" +
											"c9aa3af5f7302174" +
											"8bc3fdb124ae9b20",
									),
								},

								Signature: "dummy",
							},
						).
						Return(pow.Solution{}, dosProtectorUsecaseErrors.ErrInvalidParameters)

					httpErrorHandlerMock :=
						dosProtectorAdapterMiddlewaresMocks.NewMockhttpErrorHandler(test)
					httpErrorHandlerMock.EXPECT().
						HandleHTTPError(
							mock.AnythingOfType("*httptest.ResponseRecorder"),
							mock.AnythingOfType("string"),
							http.StatusBadRequest,
						)

					return DoSProtectorMiddlewareOptions{
						DoSProtectorUsecase: doSProtectorUsecaseMock,
						HTTPErrorHandler:    httpErrorHandlerMock.HandleHTTPError,
					}
				},
			},
			args: args{
				handler: func(test *testing.T, request *http.Request) http.Handler {
					return dosProtectorAdapterMiddlewaresMocks.NewMockhttpHandler(test)
				},
			},
			handlerArgs: handlerArgs{
				request: func() *http.Request {
					request := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
					request.Header.Set(
						dosProtectorAdapterModels.SolutionHeaderKey,
						"created-at=2000-01-02T03%3A04%3A05.000000006Z"+
							"&hash-data-layout="+
							"%7B%7B+.Challenge.LeadingZeroBitCount.ToInt+%7D%7D"+
							"%3A%7B%7B+.Challenge.SerializedPayload.ToString+%7D%7D"+
							"%3A%7B%7B+.Nonce.ToString+%7D%7D"+
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
					request.Header.Set(dosProtectorAdapterModels.SignatureHeaderKey, "dummy")

					return request
				}(),
			},
			wantResponse: mo.None[*http.Response](),
		},
		{
			name: "error" +
				"/with a solution header" +
				"/unable to verify the solution and challenge signature" +
				"/validation failure",
			fields: fields{
				options: func(test *testing.T) DoSProtectorMiddlewareOptions {
					doSProtectorUsecaseMock :=
						dosProtectorAdapterMiddlewaresMocks.NewMockDoSProtectorUsecase(test)
					doSProtectorUsecaseMock.EXPECT().
						VerifySolutionAndChallengeSignature(
							context.Background(),
							dosProtectorUsecaseModels.VerifySolutionAndChallengeSignatureParams{
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
									Nonce: "37",
									HashSum: mo.Some(
										"005d372c56e6c6b5" +
											"2ad4a8325654692e" +
											"c9aa3af5f7302174" +
											"8bc3fdb124ae9b20",
									),
								},

								Signature: "dummy",
							},
						).
						Return(pow.Solution{}, powErrors.ErrValidationFailure)

					httpErrorHandlerMock :=
						dosProtectorAdapterMiddlewaresMocks.NewMockhttpErrorHandler(test)
					httpErrorHandlerMock.EXPECT().
						HandleHTTPError(
							mock.AnythingOfType("*httptest.ResponseRecorder"),
							mock.AnythingOfType("string"),
							http.StatusForbidden,
						)

					return DoSProtectorMiddlewareOptions{
						DoSProtectorUsecase: doSProtectorUsecaseMock,
						HTTPErrorHandler:    httpErrorHandlerMock.HandleHTTPError,
					}
				},
			},
			args: args{
				handler: func(test *testing.T, request *http.Request) http.Handler {
					return dosProtectorAdapterMiddlewaresMocks.NewMockhttpHandler(test)
				},
			},
			handlerArgs: handlerArgs{
				request: func() *http.Request {
					request := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
					request.Header.Set(
						dosProtectorAdapterModels.SolutionHeaderKey,
						"created-at=2000-01-02T03%3A04%3A05.000000006Z"+
							"&hash-data-layout="+
							"%7B%7B+.Challenge.LeadingZeroBitCount.ToInt+%7D%7D"+
							"%3A%7B%7B+.Challenge.SerializedPayload.ToString+%7D%7D"+
							"%3A%7B%7B+.Nonce.ToString+%7D%7D"+
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
					request.Header.Set(dosProtectorAdapterModels.SignatureHeaderKey, "dummy")

					return request
				}(),
			},
			wantResponse: mo.None[*http.Response](),
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			middleware := DoSProtectorMiddleware{
				options: data.fields.options(test),
			}
			gotHandler :=
				middleware.ApplyTo(data.args.handler(test, data.handlerArgs.request))

			recorder := httptest.NewRecorder()
			gotHandler.ServeHTTP(recorder, data.handlerArgs.request)

			if wantResponse, isPresent := data.wantResponse.Get(); isPresent {
				assert.Equal(test, wantResponse, recorder.Result())
			}
		})
	}
}
