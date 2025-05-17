package dosProtectorAdapterModels

import (
	"net/http"
)

const (
	ChallengeHeaderKey = "X-Dos-Protector-Challenge"
	SolutionHeaderKey  = "X-Dos-Protector-Solution"
	SignatureHeaderKey = "X-Dos-Protector-Signature"
)

const (
	ResponseStatusToHEADRequest = http.StatusForbidden
)
