package dosProtectorTests

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync/atomic"

	"github.com/AlekSi/pointer"
	"github.com/samber/mo"
	dosProtectorAdapterClients "github.com/thewizardplusplus/go-dos-protector/adapters/clients"
	dosProtectorUsecases "github.com/thewizardplusplus/go-dos-protector/usecases"
	dosProtectorUsecaseProviders "github.com/thewizardplusplus/go-dos-protector/usecases/providers"
	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

func newTestHashProvider() dosProtectorUsecases.HashProvider {
	hashProvider := dosProtectorUsecaseProviders.NewMapHashProvider()
	hashProvider.RegisterHash("SHA-256", sha256.New)
	hashProvider.RegisterHash("SHA-512", sha512.New)

	return hashProvider
}

type newTestHTTPClientParams struct {
	httpClientAddressStorage *atomic.Pointer[string]
	hashProvider             dosProtectorUsecases.HashProvider
	initialNonceRandomReader io.Reader
}

func newTestHTTPClient(
	params newTestHTTPClientParams,
) dosProtectorAdapterClients.HTTPClientWrapper {
	return dosProtectorAdapterClients.NewHTTPClientWrapper(
		dosProtectorAdapterClients.HTTPClientWrapperOptions{
			HTTPClient: &http.Client{
				Transport: &http.Transport{
					DialContext: func(
						ctx context.Context,
						network string,
						address string,
					) (net.Conn, error) {
						connection, err := (&net.Dialer{}).DialContext(ctx, network, address)
						if err == nil {
							params.httpClientAddressStorage.Store(
								pointer.To(connection.LocalAddr().String()),
							)
						}

						return connection, err
					},
				},
			},
			DoSProtectorUsecase: dosProtectorUsecases.NewClientDoSProtectorUsecase(
				dosProtectorUsecases.ClientDoSProtectorUsecaseOptions{
					HashProvider: params.hashProvider,
				},
			),
			MaxAttemptCount: mo.Some(1000),
			RandomInitialNonceParams: mo.Some(powValueTypes.RandomNonceParams{
				RandomReader: params.initialNonceRandomReader,
				MinRawValue:  big.NewInt(1023),
				MaxRawValue:  big.NewInt(1042),
			}),
		},
	)
}
