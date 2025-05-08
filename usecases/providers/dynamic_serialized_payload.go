package dosProtectorUsecaseProviders

import (
	"context"
	"errors"
	"fmt"

	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

type serializedPayloadCtxKey struct{}

func WithSerializedPayload(
	ctx context.Context,
	serializedPayload powValueTypes.SerializedPayload,
) context.Context {
	return context.WithValue(ctx, serializedPayloadCtxKey{}, serializedPayload)
}

type DynamicSerializedPayload struct{}

func (provider DynamicSerializedPayload) ProvideSerializedPayload(
	ctx context.Context,
) (powValueTypes.SerializedPayload, error) {
	rawSerializedPayload := ctx.Value(serializedPayloadCtxKey{})
	if rawSerializedPayload == nil {
		return powValueTypes.SerializedPayload{}, errors.New(
			"there isn't a serialized payload in the context",
		)
	}

	serializedPayload, isAsserted :=
		rawSerializedPayload.(powValueTypes.SerializedPayload)
	if !isAsserted {
		return powValueTypes.SerializedPayload{}, fmt.Errorf(
			"serialized payload has an invalid type: %T",
			rawSerializedPayload,
		)
	}

	return serializedPayload, nil
}
