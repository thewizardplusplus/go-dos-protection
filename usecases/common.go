package dosProtectionUsecases

import (
	"context"

	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

type HashProvider interface {
	ProvideHashByName(
		ctx context.Context,
		hashName string,
	) (powValueTypes.Hash, error)
}
