package dosProtectorAdapterModels

import (
	"errors"
	"net/url"
	"strconv"

	pow "github.com/thewizardplusplus/go-pow"
)

const (
	leadingZeroBitCountKey = "leading-zero-bit-count"
	createdAtKey           = "created-at"
	ttlKey                 = "ttl"
	resourceKey            = "resource"
	payloadKey             = "payload"
	hashNameKey            = "hash-name"
	hashDataLayoutKey      = "hash-data-layout"
)

type Challenge struct {
	LeadingZeroBitCount int
	CreatedAt           string
	TTL                 string
	Resource            string
	Payload             string
	HashName            string
	HashDataLayout      string
}

func NewChallengeFromEntity(entity pow.Challenge) (Challenge, error) {
	createdAt, isPresent := entity.CreatedAt().Get()
	if !isPresent {
		return Challenge{}, errors.New("`CreatedAt` timestamp is required")
	}

	ttl, isPresent := entity.TTL().Get()
	if !isPresent {
		return Challenge{}, errors.New("TTL is required")
	}

	resource, isPresent := entity.Resource().Get()
	if !isPresent {
		return Challenge{}, errors.New("resource is required")
	}

	model := Challenge{
		LeadingZeroBitCount: entity.LeadingZeroBitCount().ToInt(),
		CreatedAt:           createdAt.ToString(),
		TTL:                 ttl.ToString(),
		Resource:            resource.ToString(),
		Payload:             entity.SerializedPayload().ToString(),
		HashName:            entity.Hash().Name(),
		HashDataLayout:      entity.HashDataLayout().ToString(),
	}
	return model, nil
}

func (model Challenge) ToQuery() string {
	values := make(url.Values)
	values.Set(leadingZeroBitCountKey, strconv.Itoa(model.LeadingZeroBitCount))
	values.Set(createdAtKey, model.CreatedAt)
	values.Set(ttlKey, model.TTL)
	values.Set(resourceKey, model.Resource)
	values.Set(payloadKey, model.Payload)
	values.Set(hashNameKey, model.HashName)
	values.Set(hashDataLayoutKey, model.HashDataLayout)

	return values.Encode()
}
