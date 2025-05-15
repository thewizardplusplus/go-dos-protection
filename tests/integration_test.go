package dosProtectorTests

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AlekSi/pointer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	dosProtectorAdapterMiddlewares "github.com/thewizardplusplus/go-dos-protector/adapters/middlewares"
	dosProtectorAdapterModels "github.com/thewizardplusplus/go-dos-protector/adapters/models"
	dosProtectorUsecases "github.com/thewizardplusplus/go-dos-protector/usecases"
	dosProtectorUsecaseProviders "github.com/thewizardplusplus/go-dos-protector/usecases/providers"
	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

type threadSafeReader struct {
	innerReader io.Reader
	mutex       sync.Mutex
}

func newThreadSafeReader(reader io.Reader) *threadSafeReader {
	return &threadSafeReader{
		innerReader: reader,
	}
}

func (reader *threadSafeReader) Read(
	buffer []byte,
) (readByteCount int, err error) {
	reader.mutex.Lock()
	defer reader.mutex.Unlock()

	readByteCount, err = reader.innerReader.Read(buffer)
	if err != nil {
		err = fmt.Errorf("unable to read the data by inner reader: %w", err)
	}
	return readByteCount, err
}

func TestDoSProtector_integration(test *testing.T) {
	type commonArgs struct {
		randomReader io.Reader
	}
	type testServerArgs struct {
		leadingZeroBitCountProvider   dosProtectorUsecases.LeadingZeroBitCountProvider
		resourceProvider              dosProtectorUsecases.ResourceProvider
		mainSerializedPayloadProvider dosProtectorUsecases.SerializedPayloadProvider
		handler                       http.Handler
		middlewares                   func(
			leadingZeroBitCountProvider dosProtectorUsecases.LeadingZeroBitCountProvider,
		) []middleware
	}
	type testHTTPClientArgs struct {
		request func(serverURL *url.URL) *http.Request
	}
	type wantRequestsParams struct {
		httpClientAddressStorage *atomic.Pointer[string]
		serverURL                *url.URL
	}

	for _, data := range []struct {
		name               string
		commonArgs         commonArgs
		testServerArgs     testServerArgs
		testHTTPClientArgs testHTTPClientArgs
		wantStatusCode     int
		wantResponseBody   []byte
		wantRequests       func(params wantRequestsParams) []*http.Request
	}{
		{
			name: "success/constant providers",
			commonArgs: commonArgs{
				randomReader: newThreadSafeReader(rand.NewChaCha8([32]byte{})),
			},
			testServerArgs: testServerArgs{
				leadingZeroBitCountProvider: func() dosProtectorUsecases.LeadingZeroBitCountProvider { //nolint:lll
					leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(5)
					require.NoError(test, err)

					return dosProtectorUsecaseProviders.NewConstantLeadingZeroBitCount(
						leadingZeroBitCount,
					)
				}(),
				resourceProvider: func() dosProtectorUsecases.ResourceProvider {
					resource, err := powValueTypes.ParseResource("https://example.com/")
					require.NoError(test, err)

					return dosProtectorUsecaseProviders.NewConstantResource(resource)
				}(),
				mainSerializedPayloadProvider: dosProtectorUsecaseProviders.NewConstantSerializedPayload( //nolint:lll
					powValueTypes.NewSerializedPayload("dummy"),
				),
				handler: func() http.Handler {
					var mux http.ServeMux
					mux.Handle("GET /api/v1/echo", http.HandlerFunc(func(
						writer http.ResponseWriter,
						request *http.Request,
					) {
						writer.Write([]byte("Hello, World!\n")) //nolint:errcheck
					}))

					return &mux
				}(),
				middlewares: func(
					leadingZeroBitCountProvider dosProtectorUsecases.LeadingZeroBitCountProvider, //nolint:lll
				) []middleware {
					return []middleware{}
				},
			},
			testHTTPClientArgs: testHTTPClientArgs{
				request: func(serverURL *url.URL) *http.Request {
					request, err := http.NewRequest(
						http.MethodGet,
						serverURL.JoinPath("/api/v1/echo").String(),
						nil,
					)
					require.NoError(test, err)

					return request
				},
			},
			wantStatusCode:   http.StatusOK,
			wantResponseBody: []byte("Hello, World!\n"),
			wantRequests: func(params wantRequestsParams) []*http.Request {
				return []*http.Request{
					{
						Method:     http.MethodHead,
						URL:        &url.URL{Path: "/api/v1/echo"},
						Proto:      "HTTP/1.1",
						ProtoMajor: 1,
						ProtoMinor: 1,
						Header: http.Header{
							"User-Agent": {"Go-http-client/1.1"},
						},
						Body:       http.NoBody,
						Host:       params.serverURL.Host,
						RemoteAddr: pointer.Get(params.httpClientAddressStorage.Load()),
						RequestURI: "/api/v1/echo",
					},
					{
						Method:     http.MethodGet,
						URL:        &url.URL{Path: "/api/v1/echo"},
						Proto:      "HTTP/1.1",
						ProtoMajor: 1,
						ProtoMinor: 1,
						Header: http.Header{
							"Accept-Encoding": {"gzip"},
							"User-Agent":      {"Go-http-client/1.1"},
							dosProtectorAdapterModels.SolutionHeaderKey: {
								"created-at=1999-09-04T00%3A00%3A00Z" +
									"&hash-data-layout=" +
									"%7B%7B.Challenge.LeadingZeroBitCount.ToInt%7D%7D" +
									"%7B%7B.Challenge.CreatedAt.MustGet.ToString%7D%7D" +
									"%7B%7B.Challenge.TTL.MustGet.ToString%7D%7D" +
									"%7B%7B.Challenge.Resource.MustGet.ToString%7D%7D" +
									"%7B%7B.Challenge.SerializedPayload.ToString%7D%7D" +
									"%7B%7B.Challenge.Hash.Name%7D%7D" +
									"%7B%7B.Challenge.HashDataLayout.ToString%7D%7D" +
									"%7B%7B.Nonce.ToString%7D%7D" +
									"&hash-name=SHA-256" +
									"&hash-sum=" +
									"0555940cb7fefbf5" +
									"15fcbeb15b790f8d" +
									"ca5adf8a26ee528d" +
									"98deb0f00e75b307" +
									"&leading-zero-bit-count=5" +
									"&nonce=1036" +
									"&payload=dummyd9877ece6d" +
									"&resource=https%3A%2F%2Fexample.com%2F" +
									"&ttl=" + (100 * 365 * 24 * time.Hour).String(),
							},
							dosProtectorAdapterModels.SignatureHeaderKey: {
								"4dfa83403660a20b" +
									"dbba8fff0c7ea93a" +
									"33e3ddd27ad3709e" +
									"1e576002f381bfaf" +
									"9ad3478998971f75" +
									"531a14df1087a10d" +
									"1139852ffc5f2ad7" +
									"fa5b854901a415c8",
							},
						},
						Body:       http.NoBody,
						Host:       params.serverURL.Host,
						RemoteAddr: pointer.Get(params.httpClientAddressStorage.Load()),
						RequestURI: "/api/v1/echo",
					},
				}
			},
		},
		{
			name: "success/dynamic providers",
			commonArgs: commonArgs{
				randomReader: newThreadSafeReader(rand.NewChaCha8([32]byte{})),
			},
			testServerArgs: testServerArgs{
				leadingZeroBitCountProvider: func() dosProtectorUsecases.LeadingZeroBitCountProvider { //nolint:lll
					leadingZeroBitCountProvider, err :=
						dosProtectorUsecaseProviders.NewDynamicLeadingZeroBitCount(
							dosProtectorUsecaseProviders.DynamicLeadingZeroBitCountOptions{
								MinConsideredLoadLevel: 1e3,
								MaxConsideredLoadLevel: 1e4,
								MinRawValue:            5,
								MaxRawValue:            10,
							},
						)
					require.NoError(test, err)

					return leadingZeroBitCountProvider
				}(),
				resourceProvider:              dosProtectorUsecaseProviders.DynamicResource{},          //nolint:lll
				mainSerializedPayloadProvider: dosProtectorUsecaseProviders.DynamicSerializedPayload{}, //nolint:lll
				handler: func() http.Handler {
					var mux http.ServeMux
					mux.Handle("GET /api/v1/echo", http.HandlerFunc(func(
						writer http.ResponseWriter,
						request *http.Request,
					) {
						writer.Write([]byte("Hello, World!\n")) //nolint:errcheck
					}))

					return &mux
				}(),
				middlewares: func(
					leadingZeroBitCountProvider dosProtectorUsecases.LeadingZeroBitCountProvider, //nolint:lll
				) []middleware {
					serializedPayloadMiddleware := func(handler http.Handler) http.Handler {
						return http.HandlerFunc(func(
							writer http.ResponseWriter,
							request *http.Request,
						) {
							handler.ServeHTTP(
								writer,
								request.WithContext(dosProtectorUsecaseProviders.WithSerializedPayload(
									request.Context(),
									powValueTypes.NewSerializedPayload(request.Header.Get("User-Agent")),
								)),
							)
						})
					}
					resourceMiddleware :=
						dosProtectorAdapterMiddlewares.NewResourceMiddleware(
							dosProtectorAdapterMiddlewares.ResourceMiddlewareOptions{
								HostMode: dosProtectorAdapterMiddlewares.UseURLAsIs,
							},
						)
					loadLevelMiddleware :=
						dosProtectorAdapterMiddlewares.NewLoadLevelMiddleware(
							dosProtectorAdapterMiddlewares.LoadLevelMiddlewareOptions{
								LoadLevelRegister: leadingZeroBitCountProvider.(dosProtectorAdapterMiddlewares.LoadLevelRegister), //nolint:lll
							},
						)
					return []middleware{
						serializedPayloadMiddleware,
						resourceMiddleware.ApplyTo,
						loadLevelMiddleware.ApplyTo,
					}
				},
			},
			testHTTPClientArgs: testHTTPClientArgs{
				request: func(serverURL *url.URL) *http.Request {
					request, err := http.NewRequest(
						http.MethodGet,
						serverURL.JoinPath("/api/v1/echo").String(),
						nil,
					)
					require.NoError(test, err)

					return request
				},
			},
			wantStatusCode:   http.StatusOK,
			wantResponseBody: []byte("Hello, World!\n"),
			wantRequests: func(params wantRequestsParams) []*http.Request {
				return []*http.Request{
					{
						Method:     http.MethodHead,
						URL:        &url.URL{Path: "/api/v1/echo"},
						Proto:      "HTTP/1.1",
						ProtoMajor: 1,
						ProtoMinor: 1,
						Header: http.Header{
							"User-Agent": {"Go-http-client/1.1"},
						},
						Body:       http.NoBody,
						Host:       params.serverURL.Host,
						RemoteAddr: pointer.Get(params.httpClientAddressStorage.Load()),
						RequestURI: "/api/v1/echo",
					},
					{
						Method:     http.MethodGet,
						URL:        &url.URL{Path: "/api/v1/echo"},
						Proto:      "HTTP/1.1",
						ProtoMajor: 1,
						ProtoMinor: 1,
						Header: http.Header{
							"Accept-Encoding": {"gzip"},
							"User-Agent":      {"Go-http-client/1.1"},
							dosProtectorAdapterModels.SolutionHeaderKey: {
								"created-at=1999-09-04T00%3A00%3A00Z" +
									"&hash-data-layout=" +
									"%7B%7B.Challenge.LeadingZeroBitCount.ToInt%7D%7D" +
									"%7B%7B.Challenge.CreatedAt.MustGet.ToString%7D%7D" +
									"%7B%7B.Challenge.TTL.MustGet.ToString%7D%7D" +
									"%7B%7B.Challenge.Resource.MustGet.ToString%7D%7D" +
									"%7B%7B.Challenge.SerializedPayload.ToString%7D%7D" +
									"%7B%7B.Challenge.Hash.Name%7D%7D" +
									"%7B%7B.Challenge.HashDataLayout.ToString%7D%7D" +
									"%7B%7B.Nonce.ToString%7D%7D" +
									"&hash-name=SHA-256" +
									"&hash-sum=" +
									"03678dceefc32244" +
									"0527f4063cd25f0f" +
									"a2c042d874013119" +
									"f0cf43a14d360e3a" +
									"&leading-zero-bit-count=5" +
									"&nonce=1033" +
									"&payload=Go-http-client%2F1.1d9877ece6d" +
									"&resource=%2Fapi%2Fv1%2Fecho" +
									"&ttl=" + (100 * 365 * 24 * time.Hour).String(),
							},
							dosProtectorAdapterModels.SignatureHeaderKey: {
								"87ec3cf29b0c1d0e" +
									"d5bc8373cb19c2ff" +
									"d6bbfe3441866892" +
									"93da973486f72b95" +
									"29bbe6d6c5ad8e19" +
									"87b3a90d5c2f37da" +
									"b15b0c87aea08ad5" +
									"b727164b74ee2a6c",
							},
						},
						Body:       http.NoBody,
						Host:       params.serverURL.Host,
						RemoteAddr: pointer.Get(params.httpClientAddressStorage.Load()),
						RequestURI: "/api/v1/echo",
					},
				}
			},
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			hashProvider := newTestHashProvider()

			gotRequestChannel := make(chan *http.Request, 1000)
			server, err := newTestServer(newTestServerParams{
				leadingZeroBitCountProvider:   data.testServerArgs.leadingZeroBitCountProvider, //nolint:lll
				resourceProvider:              data.testServerArgs.resourceProvider,
				mainSerializedPayloadProvider: data.testServerArgs.mainSerializedPayloadProvider, //nolint:lll
				randomPayloadByteReader:       data.commonArgs.randomReader,
				hashProvider:                  hashProvider,
				gotRequestChannel:             gotRequestChannel,
				handler:                       data.testServerArgs.handler,
				middlewares: data.testServerArgs.middlewares(
					data.testServerArgs.leadingZeroBitCountProvider,
				),
			})
			require.NoError(test, err)
			defer server.Close()

			serverURL, err := url.Parse(server.URL)
			require.NoError(test, err)

			var httpClientAddressStorage atomic.Pointer[string]
			httpClient := newTestHTTPClient(newTestHTTPClientParams{
				httpClientAddressStorage: &httpClientAddressStorage,
				hashProvider:             hashProvider,
				initialNonceRandomReader: data.commonArgs.randomReader,
			})

			response, err := httpClient.Do(data.testHTTPClientArgs.request(serverURL))
			require.NoError(test, err)
			defer response.Body.Close()

			responseBody, err := io.ReadAll(response.Body)
			require.NoError(test, err)

			assert.Equal(test, data.wantStatusCode, response.StatusCode)
			assert.Equal(test, data.wantResponseBody, responseBody)

			wantRequests := data.wantRequests(wantRequestsParams{
				httpClientAddressStorage: &httpClientAddressStorage,
				serverURL:                serverURL,
			})
			for index := range wantRequests {
				wantRequests[index] = wantRequests[index].WithContext(context.Background())
			}

			close(gotRequestChannel)

			var gotRequests []*http.Request
			for gotRequest := range gotRequestChannel {
				gotRequests = append(gotRequests, gotRequest)
			}

			assert.Equal(test, wantRequests, gotRequests)
		})
	}
}
