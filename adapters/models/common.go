package dosProtectorAdapterModels

import (
	"fmt"
	"net/url"
	"strconv"
)

func newChallengeFromValues(values url.Values) (Challenge, error) {
	leadingZeroBitCount, err := strconv.Atoi(values.Get(LeadingZeroBitCountKey))
	if err != nil {
		return Challenge{}, fmt.Errorf(
			"unable to parse the leading zero bit count: %w",
			err,
		)
	}

	model := Challenge{
		LeadingZeroBitCount: leadingZeroBitCount,
		CreatedAt:           values.Get(CreatedAtKey),
		TTL:                 values.Get(TTLKey),
		Resource:            values.Get(ResourceKey),
		Payload:             values.Get(PayloadKey),
		HashName:            values.Get(HashNameKey),
		HashDataLayout:      values.Get(HashDataLayoutKey),
	}
	return model, nil
}

func transformChallengeToValues(model Challenge) url.Values {
	values := make(url.Values)
	values.Set(LeadingZeroBitCountKey, strconv.Itoa(model.LeadingZeroBitCount))
	values.Set(CreatedAtKey, model.CreatedAt)
	values.Set(TTLKey, model.TTL)
	values.Set(ResourceKey, model.Resource)
	values.Set(PayloadKey, model.Payload)
	values.Set(HashNameKey, model.HashName)
	values.Set(HashDataLayoutKey, model.HashDataLayout)

	return values
}
