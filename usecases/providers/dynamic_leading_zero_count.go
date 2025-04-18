package dosProtectorUsecaseProviders

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync/atomic"

	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

type DynamicLeadingZeroBitCountOptions struct {
	MinConsideredLoadLevel int
	MaxConsideredLoadLevel int
	MinRawValue            int
	MaxRawValue            int
}

type DynamicLeadingZeroBitCount struct {
	options   DynamicLeadingZeroBitCountOptions
	loadLevel atomic.Int64
}

func NewDynamicLeadingZeroBitCount(
	options DynamicLeadingZeroBitCountOptions,
) (*DynamicLeadingZeroBitCount, error) {
	consideredLoadLevelRange :=
		options.MaxConsideredLoadLevel - options.MinConsideredLoadLevel
	if consideredLoadLevelRange < 0 {
		return nil, errors.New("considered load level range cannot be negative")
	}
	if consideredLoadLevelRange == 0 {
		return nil, errors.New("considered load level range cannot be zero")
	}

	rawValueRange := options.MaxRawValue - options.MinRawValue
	if rawValueRange < 0 {
		return nil, errors.New("raw value range cannot be negative")
	}
	if rawValueRange == 0 {
		return nil, errors.New("raw value range cannot be zero")
	}

	provider := &DynamicLeadingZeroBitCount{
		options: options,
	}
	return provider, nil
}

func (provider *DynamicLeadingZeroBitCount) IncreaseLoadLevel(delta int) {
	provider.loadLevel.Add(int64(delta))
}

func (provider *DynamicLeadingZeroBitCount) DecreaseLoadLevel(delta int) {
	provider.loadLevel.Add(-int64(delta))
}

func (provider *DynamicLeadingZeroBitCount) ProvideLeadingZeroBitCount(
	ctx context.Context,
) (powValueTypes.LeadingZeroBitCount, error) {
	minConsideredLoadLevel := int64(provider.options.MinConsideredLoadLevel)
	maxConsideredLoadLevel := int64(provider.options.MaxConsideredLoadLevel)

	loadLevel := provider.loadLevel.Load()
	if loadLevel < minConsideredLoadLevel {
		loadLevel = minConsideredLoadLevel
	}
	if loadLevel > maxConsideredLoadLevel {
		loadLevel = maxConsideredLoadLevel
	}

	loadLevelInPercent := float64(loadLevel-minConsideredLoadLevel) /
		float64(maxConsideredLoadLevel-minConsideredLoadLevel)

	rawValueRange := provider.options.MaxRawValue - provider.options.MinRawValue
	rawValue := float64(rawValueRange)*loadLevelInPercent +
		float64(provider.options.MinRawValue)
	value, err := powValueTypes.NewLeadingZeroBitCount(int(math.Round(rawValue)))
	if err != nil {
		return powValueTypes.LeadingZeroBitCount{}, fmt.Errorf(
			"unable to construct the leading zero bit count: %w",
			err,
		)
	}

	return value, nil
}
