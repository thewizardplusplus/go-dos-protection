package dosProtector

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"math/big"
	"net/http"

	"github.com/samber/mo"
	dosProtectorAdapterClients "github.com/thewizardplusplus/go-dos-protector/adapters/clients"
	dosProtectorUsecases "github.com/thewizardplusplus/go-dos-protector/usecases"
	dosProtectorUsecaseProviders "github.com/thewizardplusplus/go-dos-protector/usecases/providers"
	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

func newExampleHashProvider() dosProtectorUsecases.HashProvider {
	hashProvider := dosProtectorUsecaseProviders.NewMapHashProvider()
	hashProvider.RegisterHash("SHA-256", sha256.New)
	hashProvider.RegisterHash("SHA-512", sha512.New)

	return hashProvider
}

func newExampleHTTPClient(
	hashProvider dosProtectorUsecases.HashProvider,
) dosProtectorAdapterClients.HTTPClientWrapper {
	return dosProtectorAdapterClients.NewHTTPClientWrapper(
		dosProtectorAdapterClients.HTTPClientWrapperOptions{
			HTTPClient: http.DefaultClient,
			DoSProtectorUsecase: dosProtectorUsecases.NewClientDoSProtectorUsecase(
				dosProtectorUsecases.ClientDoSProtectorUsecaseOptions{
					HashProvider: hashProvider,
				},
			),
			MaxAttemptCount: mo.Some(1000),
			RandomInitialNonceParams: mo.Some(powValueTypes.RandomNonceParams{
				RandomReader: rand.Reader,
				MinRawValue:  big.NewInt(1023),
				MaxRawValue:  big.NewInt(1042),
			}),
		},
	)
}
