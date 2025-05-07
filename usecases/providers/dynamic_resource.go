package dosProtectorUsecaseProviders

import (
	"context"
	"errors"
	"fmt"

	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

type resourceCtxKey struct{}

func WithResource(
	ctx context.Context,
	resource powValueTypes.Resource,
) context.Context {
	return context.WithValue(ctx, resourceCtxKey{}, resource)
}

type DynamicResource struct{}

func (provider DynamicResource) ProvideResource(
	ctx context.Context,
) (powValueTypes.Resource, error) {
	rawResource := ctx.Value(resourceCtxKey{})
	if rawResource == nil {
		return powValueTypes.Resource{}, errors.New(
			"there isn't a resource in the context",
		)
	}

	resource, isAsserted := rawResource.(powValueTypes.Resource)
	if !isAsserted {
		return powValueTypes.Resource{}, fmt.Errorf(
			"resource has an invalid type: %T",
			rawResource,
		)
	}

	return resource, nil
}
