package dosProtectionUsecaseModels

import (
	"github.com/samber/mo"
)

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
