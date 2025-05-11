package dosProtectorAdapterModels

import (
	"encoding/hex"
	"fmt"

	"github.com/samber/mo"
	pow "github.com/thewizardplusplus/go-pow"
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
