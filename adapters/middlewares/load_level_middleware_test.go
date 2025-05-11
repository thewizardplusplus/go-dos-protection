package dosProtectorAdapterMiddlewares

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	dosProtectorAdapterMiddlewaresMocks "github.com/thewizardplusplus/go-dos-protector/mocks/github.com/thewizardplusplus/go-dos-protector/adapters/middlewares"
	dosProtectorUsecaseProviders "github.com/thewizardplusplus/go-dos-protector/usecases/providers"
)

func TestDynamicLeadingZeroBitCount_interface(test *testing.T) {
	assert.Implements(
		test,
		(*LoadLevelRegister)(nil),
		&dosProtectorUsecaseProviders.DynamicLeadingZeroBitCount{},
	)
}

func TestNewLoadLevelMiddleware(test *testing.T) {
	type args struct {
		options func(test *testing.T) LoadLevelMiddlewareOptions
	}

	for _, data := range []struct {
		name string
		args args
		want func(test *testing.T) LoadLevelMiddleware
	}{
		{
			name: "success",
			args: args{
				options: func(test *testing.T) LoadLevelMiddlewareOptions {
					loadLevelRegisterMock :=
						dosProtectorAdapterMiddlewaresMocks.NewMockLoadLevelRegister(test)
					return LoadLevelMiddlewareOptions{
						LoadLevelRegister: loadLevelRegisterMock,
					}
				},
			},
			want: func(test *testing.T) LoadLevelMiddleware {
				loadLevelRegisterMock :=
					dosProtectorAdapterMiddlewaresMocks.NewMockLoadLevelRegister(test)
				return LoadLevelMiddleware{
					options: LoadLevelMiddlewareOptions{
						LoadLevelRegister: loadLevelRegisterMock,
					},
				}
			},
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			got := NewLoadLevelMiddleware(data.args.options(test))

			assert.Equal(test, data.want(test), got)
		})
	}
}

func TestLoadLevelMiddleware_ApplyTo(test *testing.T) {
	type fields struct {
		options func(test *testing.T, calls chan string) LoadLevelMiddlewareOptions
	}
	type args struct {
		handler func(test *testing.T, calls chan string) http.Handler
	}
	type handlerArgs struct {
		writer  http.ResponseWriter
		request *http.Request
	}

	for _, data := range []struct {
		name        string
		fields      fields
		args        args
		handlerArgs handlerArgs
		wantPanic   assert.PanicAssertionFunc
		wantCalls   []string
	}{
		{
			name: "success/without a panic",
			fields: fields{
				options: func(
					test *testing.T,
					calls chan string,
				) LoadLevelMiddlewareOptions {
					loadLevelRegisterMock :=
						dosProtectorAdapterMiddlewaresMocks.NewMockLoadLevelRegister(test)
					loadLevelRegisterMock.EXPECT().
						IncreaseLoadLevel(1).
						Run(func(delta int) { calls <- "IncreaseLoadLevel" })
					loadLevelRegisterMock.EXPECT().
						DecreaseLoadLevel(1).
						Run(func(delta int) { calls <- "DecreaseLoadLevel" })

					return LoadLevelMiddlewareOptions{
						LoadLevelRegister: loadLevelRegisterMock,
					}
				},
			},
			args: args{
				handler: func(test *testing.T, calls chan string) http.Handler {
					handlerMock := dosProtectorAdapterMiddlewaresMocks.NewMockhttpHandler(test)
					handlerMock.EXPECT().
						ServeHTTP(
							httptest.NewRecorder(),
							httptest.NewRequest(http.MethodGet, "https://example.com/", nil),
						).
						Run(func(writer http.ResponseWriter, request *http.Request) {
							calls <- "ServeHTTP"
						})

					return handlerMock
				},
			},
			handlerArgs: handlerArgs{
				writer:  httptest.NewRecorder(),
				request: httptest.NewRequest(http.MethodGet, "https://example.com/", nil),
			},
			wantPanic: assert.NotPanics,
			wantCalls: []string{"IncreaseLoadLevel", "ServeHTTP", "DecreaseLoadLevel"},
		},
		{
			name: "success/with a panic",
			fields: fields{
				options: func(
					test *testing.T,
					calls chan string,
				) LoadLevelMiddlewareOptions {
					loadLevelRegisterMock :=
						dosProtectorAdapterMiddlewaresMocks.NewMockLoadLevelRegister(test)
					loadLevelRegisterMock.EXPECT().
						IncreaseLoadLevel(1).
						Run(func(delta int) { calls <- "IncreaseLoadLevel" })
					loadLevelRegisterMock.EXPECT().
						DecreaseLoadLevel(1).
						Run(func(delta int) { calls <- "DecreaseLoadLevel" })

					return LoadLevelMiddlewareOptions{
						LoadLevelRegister: loadLevelRegisterMock,
					}
				},
			},
			args: args{
				handler: func(test *testing.T, calls chan string) http.Handler {
					handlerMock := dosProtectorAdapterMiddlewaresMocks.NewMockhttpHandler(test)
					handlerMock.EXPECT().
						ServeHTTP(
							httptest.NewRecorder(),
							httptest.NewRequest(http.MethodGet, "https://example.com/", nil),
						).
						Run(func(writer http.ResponseWriter, request *http.Request) {
							calls <- "ServeHTTP"
							panic(iotest.ErrTimeout)
						})

					return handlerMock
				},
			},
			handlerArgs: handlerArgs{
				writer:  httptest.NewRecorder(),
				request: httptest.NewRequest(http.MethodGet, "https://example.com/", nil),
			},
			wantPanic: assert.Panics,
			wantCalls: []string{"IncreaseLoadLevel", "ServeHTTP", "DecreaseLoadLevel"},
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			calls := make(chan string, len(data.wantCalls))

			middleware := LoadLevelMiddleware{
				options: data.fields.options(test, calls),
			}
			gotHandler := middleware.ApplyTo(data.args.handler(test, calls))
			data.wantPanic(test, func() {
				gotHandler.ServeHTTP(data.handlerArgs.writer, data.handlerArgs.request)
			})

			close(calls)

			gotCalls := make([]string, 0, len(data.wantCalls))
			for call := range calls {
				gotCalls = append(gotCalls, call)
			}

			assert.Equal(test, data.wantCalls, gotCalls)
		})
	}
}
