package dosProtectorAdapterMiddlewares

import (
	"net/http"
)

// this interface is used only for generating mocks
type httpHandler interface { //nolint:unused
	http.Handler
}
