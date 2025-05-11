package dosProtectorAdapterModels

import (
	"net/url"
	"strconv"
)

func transformChallengeToValues(model Challenge) url.Values {
	values := make(url.Values)
	values.Set(leadingZeroBitCountKey, strconv.Itoa(model.LeadingZeroBitCount))
	values.Set(createdAtKey, model.CreatedAt)
	values.Set(ttlKey, model.TTL)
	values.Set(resourceKey, model.Resource)
	values.Set(payloadKey, model.Payload)
	values.Set(hashNameKey, model.HashName)
	values.Set(hashDataLayoutKey, model.HashDataLayout)

	return values
}
