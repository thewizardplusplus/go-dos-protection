package dosProtectorUsecaseProviders

import (
	"context"
	"fmt"
	"hash"

	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

type RawHashConstructor func() hash.Hash

type MapHashProvider struct {
	rawHashConstructorsByHashNames map[string]RawHashConstructor
}

func NewMapHashProvider() MapHashProvider {
	return MapHashProvider{
		rawHashConstructorsByHashNames: make(map[string]RawHashConstructor),
	}
}

func (provider MapHashProvider) RegisterHash(
	hashName string,
	rawHashConstructor RawHashConstructor,
) {
	provider.rawHashConstructorsByHashNames[hashName] = rawHashConstructor
}

func (provider MapHashProvider) ProvideHashByName(
	ctx context.Context,
	hashName string,
) (powValueTypes.Hash, error) {
	rawHashConstructor, isFound :=
		provider.rawHashConstructorsByHashNames[hashName]
	if !isFound {
		return powValueTypes.Hash{}, fmt.Errorf("unknown hash name: %q", hashName)
	}

	return powValueTypes.NewHash(rawHashConstructor()), nil
}
