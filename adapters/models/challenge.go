package dosProtectorAdapterModels

import (
	"errors"
	"fmt"
	"net/url"

	pow "github.com/thewizardplusplus/go-pow"
)

const (
	LeadingZeroBitCountKey = "leading-zero-bit-count"
	CreatedAtKey           = "created-at"
	TTLKey                 = "ttl"
	ResourceKey            = "resource"
	PayloadKey             = "payload"
	HashNameKey            = "hash-name"
	HashDataLayoutKey      = "hash-data-layout"
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

type SignedChallenge struct {
	Challenge

	Signature string
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

func ParseChallengeFromQuery(query string) (Challenge, error) {
	values, err := url.ParseQuery(query)
	if err != nil {
		return Challenge{}, fmt.Errorf("unable to parse the query: %w", err)
	}

	model, err := newChallengeFromValues(values)
	if err != nil {
		return Challenge{}, fmt.Errorf(
			"unable to construct the challenge from the values: %w",
			err,
		)
	}

	return model, nil
}

func (model Challenge) ToQuery() string {
	return transformChallengeToValues(model).Encode()
}
