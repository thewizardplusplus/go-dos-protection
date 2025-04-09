package dosProtectionUsecaseProviders

import (
	"context"

	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

type ConstantResource struct {
	resource powValueTypes.Resource
}

func NewConstantResource(resource powValueTypes.Resource) ConstantResource {
	return ConstantResource{
		resource: resource,
	}
}

func (provider ConstantResource) ProvideResource(
	ctx context.Context,
) (powValueTypes.Resource, error) {
	return provider.resource, nil
}
