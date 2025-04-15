package dosProtectorUsecaseProviders

import (
	"context"

	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

type ConstantSerializedPayload struct {
	serializedPayload powValueTypes.SerializedPayload
}

func NewConstantSerializedPayload(
	serializedPayload powValueTypes.SerializedPayload,
) ConstantSerializedPayload {
	return ConstantSerializedPayload{
		serializedPayload: serializedPayload,
	}
}

func (provider ConstantSerializedPayload) ProvideSerializedPayload(
	ctx context.Context,
) (powValueTypes.SerializedPayload, error) {
	return provider.serializedPayload, nil
}
