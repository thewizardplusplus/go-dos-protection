package dosProtectorAdapterModels

import (
	"net/url"
	"strconv"
)

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
