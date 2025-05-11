package dosProtectorAdapterModels

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"

	"github.com/samber/mo"
	pow "github.com/thewizardplusplus/go-pow"
)

const (
	nonceKey   = "nonce"
	hashSumKey = "hash-sum"
)

type Solution struct {
	Challenge

	Nonce   string
	HashSum mo.Option[string]
}

func NewSolutionFromEntity(entity pow.Solution) (Solution, error) {
	challenge, err := NewChallengeFromEntity(entity.Challenge())
	if err != nil {
		return Solution{}, fmt.Errorf("unable to construct the challenge: %w", err)
	}

	var rawHashSum mo.Option[string]
	if hashSum, isPresent := entity.HashSum().Get(); isPresent {
		rawHashSum = mo.Some(hex.EncodeToString(hashSum.ToBytes()))
	}

	model := Solution{
		Challenge: challenge,

		Nonce:   entity.Nonce().ToString(),
		HashSum: rawHashSum,
	}
	return model, nil
}

func (model Solution) ToQuery() string {
	values := make(url.Values)
	values.Set(leadingZeroBitCountKey, strconv.Itoa(model.LeadingZeroBitCount))
	values.Set(createdAtKey, model.CreatedAt)
	values.Set(ttlKey, model.TTL)
	values.Set(resourceKey, model.Resource)
	values.Set(payloadKey, model.Payload)
	values.Set(hashNameKey, model.HashName)
	values.Set(hashDataLayoutKey, model.HashDataLayout)
	values.Set(nonceKey, model.Nonce)
	if hashSum, isPresent := model.HashSum.Get(); isPresent {
		values.Set(hashSumKey, hashSum)
	}

	return values.Encode()
}
