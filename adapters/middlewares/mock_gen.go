package dosProtectorAdapterMiddlewares

import (
	"net/http"
)

// this interface is used only for generating mocks
type httpHandler interface { //nolint:unused
	http.Handler
}

// this interface is used only for generating mocks
type httpErrorHandler interface { //nolint:unused
	HandleHTTPError(
		writer http.ResponseWriter,
		err string,
		statusCode int,
	)
}
