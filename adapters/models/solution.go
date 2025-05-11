package dosProtectorAdapterModels

import (
	"encoding/hex"
	"fmt"
	"net/url"

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

func ParseSolutionFromQuery(query string) (Solution, error) {
	challenge, err := ParseChallengeFromQuery(query)
	if err != nil {
		return Solution{}, fmt.Errorf("unable to parse the challenge: %w", err)
	}

	values, err := url.ParseQuery(query)
	if err != nil {
		return Solution{}, fmt.Errorf("unable to parse the query: %w", err)
	}

	model := Solution{
		Challenge: challenge,

		Nonce:   values.Get(nonceKey),
		HashSum: mo.EmptyableToOption(values.Get(hashSumKey)),
	}
	return model, nil
}

func (model Solution) ToQuery() string {
	values := transformChallengeToValues(model.Challenge)
	values.Set(nonceKey, model.Nonce)
	if hashSum, isPresent := model.HashSum.Get(); isPresent {
		values.Set(hashSumKey, hashSum)
	}

	return values.Encode()
}
