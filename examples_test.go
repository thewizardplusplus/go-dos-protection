package dosProtector

import (
	"fmt"
	"io"
	"log"
	"net/http"

	dosProtectorUsecaseProviders "github.com/thewizardplusplus/go-dos-protector/usecases/providers"
	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

func Example_constantProviders() {
	hashProvider := newExampleHashProvider()

	leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(5)
	if err != nil {
		log.Fatalf("unable to construct the leading zero bit count: %s", err)
	}

	resource, err := powValueTypes.ParseResource("https://example.com/")
	if err != nil {
		log.Fatalf("unable to construct the resource: %s", err)
	}

	var mux http.ServeMux
	mux.Handle("GET /api/v1/echo", http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		writer.Write([]byte("Hello, World!\n")) //nolint:errcheck
	}))

	leadingZeroBitCountProvider :=
		dosProtectorUsecaseProviders.NewConstantLeadingZeroBitCount(
			leadingZeroBitCount,
		)
	resourceProvider := dosProtectorUsecaseProviders.NewConstantResource(resource)
	mainSerializedPayloadProvider :=
		dosProtectorUsecaseProviders.NewConstantSerializedPayload(
			powValueTypes.NewSerializedPayload("dummy"),
		)
	server, err := newExampleServer(newExampleServerParams{
		leadingZeroBitCountProvider:   leadingZeroBitCountProvider,
		resourceProvider:              resourceProvider,
		mainSerializedPayloadProvider: mainSerializedPayloadProvider,
		hashProvider:                  hashProvider,
		handler:                       &mux,
		middlewares:                   []middleware{},
	})
	if err != nil {
		log.Fatalf("unable to construct the example server: %s", err)
	}
	defer server.Close()

	request, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/echo", nil)
	if err != nil {
		log.Fatalf("unable to construct the request: %s", err)
	}

	httpClient := newExampleHTTPClient(hashProvider)
	response, err := httpClient.Do(request)
	if err != nil {
		log.Fatalf("unable to send the request: %s", err)
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("unable to read the response body: %s", err)
	}

	fmt.Println(response.Status)
	fmt.Print(string(responseBody))

	// Output:
	// 200 OK
	// Hello, World!
}
