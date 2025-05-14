package dosProtectorAdapterClients

import (
	"context"
	"net/http"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	dosProtectorAdapterModels "github.com/thewizardplusplus/go-dos-protector/adapters/models"
	dosProtectorAdapterClientsMocks "github.com/thewizardplusplus/go-dos-protector/mocks/github.com/thewizardplusplus/go-dos-protector/adapters/clients"
)

func TestHTTPClient_interface(test *testing.T) {
	assert.Implements(test, (*HTTPClient)(nil), &http.Client{})
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
								StatusCode: http.StatusForbidden,
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
											"&ttl=" + (100 * 365 * 24 * time.Hour).String(),
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
					TTL:                 (100 * 365 * 24 * time.Hour).String(),
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
						Return(&http.Response{StatusCode: http.StatusForbidden}, nil)

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
								StatusCode: http.StatusForbidden,
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
								StatusCode: http.StatusForbidden,
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
											"&ttl=" + (100 * 365 * 24 * time.Hour).String(),
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
