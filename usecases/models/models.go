package dosProtectionUsecaseModels

import (
	"github.com/samber/mo"
	"github.com/thewizardplusplus/go-pow"
	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

type SolveChallengeParams struct {
	LeadingZeroBitCount      int
	CreatedAt                string
	TTL                      string
	Resource                 string
	Payload                  string
	HashName                 string
	HashDataLayout           string
	MaxAttemptCount          mo.Option[int]
	RandomInitialNonceParams mo.Option[powValueTypes.RandomNonceParams]
}

type VerifySolutionParams struct {
	LeadingZeroBitCount int
	CreatedAt           string
	TTL                 string
	Resource            string
	Payload             string
	HashName            string
	HashDataLayout      string
	Nonce               string
	HashSum             mo.Option[string]
}

type SignedChallenge struct {
	Challenge                 pow.Challenge
	MessageAuthenticationCode string
}
