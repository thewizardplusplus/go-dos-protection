package dosProtectorUsecaseProviders

import (
	"context"

	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

type ConstantLeadingZeroBitCount struct {
	leadingZeroBitCount powValueTypes.LeadingZeroBitCount
}

func NewConstantLeadingZeroBitCount(
	leadingZeroBitCount powValueTypes.LeadingZeroBitCount,
) ConstantLeadingZeroBitCount {
	return ConstantLeadingZeroBitCount{
		leadingZeroBitCount: leadingZeroBitCount,
	}
}

func (provider ConstantLeadingZeroBitCount) ProvideLeadingZeroBitCount(
	ctx context.Context,
) (powValueTypes.LeadingZeroBitCount, error) {
	return provider.leadingZeroBitCount, nil
}
