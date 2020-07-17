package sandbox

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/getyoti/yoti-go-sdk/v3/docscan/sandbox/request"
	"github.com/getyoti/yoti-go-sdk/v3/requests"
	yotirequest "github.com/getyoti/yoti-go-sdk/v3/requests"
)

type jsonMarshaler interface {
	Marshal(v interface{}) ([]byte, error)
}

// Client is responsible for setting up test data in the sandbox instance. BaseURL is not required.
type Client struct {
	// Client SDK ID. This can be found in the Yoti Hub after you have created and activated an application.
	ClientSdkID string
	// Private Key associated for your application, can be downloaded from the Yoti Hub.
	Key *rsa.PrivateKey
	// Base URL to use. This is not required, and a default will be set if not provided.
	BaseURL string
	// Mockable HTTP Client Interface
	HTTPClient requests.HttpClient
	// Mockable JSON marshaler
	jsonMarshaler jsonMarshaler
}

func (client *Client) getHTTPClient() requests.HttpClient {
	if client.HTTPClient != nil {
		return client.HTTPClient
	}
	return http.DefaultClient
}

func (client *Client) marshalJSON(v interface{}) ([]byte, error) {
	if client.jsonMarshaler != nil {
		return client.jsonMarshaler.Marshal(v)
	}
	return json.Marshal(v)
}

func (client *Client) getAPIURL() string {
	if client.BaseURL == "" {
		if value, exists := os.LookupEnv("YOTI_DOC_SCAN_API_URL"); exists && value != "" {
			client.BaseURL = value
		} else {
			client.BaseURL = "https://api.yoti.com/sandbox/idverify/v1"
		}
	}
	return client.BaseURL
}

func (client *Client) makeConfigureResponseRequest(request *http.Request) (err error) {
	response, err := client.getHTTPClient().Do(request)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusCreated {
		body, _ := ioutil.ReadAll(response.Body)
		return fmt.Errorf("Response config not created (HTTP %d) %s", response.StatusCode, string(body))
	}

	return nil
}

// ConfigureSessionResponse configures the response for the session
func (client *Client) ConfigureSessionResponse(sessionID string, responseConfig request.ResponseConfig) (err error) {
	requestEndpoint := "/sessions/" + sessionID + "/response-config"
	requestBody, err := client.marshalJSON(responseConfig)
	if err != nil {
		return err
	}

	request, err := (&yotirequest.SignedRequest{
		Key:        client.Key,
		HTTPMethod: "PUT",
		BaseURL:    client.getAPIURL(),
		Endpoint:   requestEndpoint,
		Headers:    yotirequest.JSONHeaders(),
		Body:       requestBody,
		Params:     map[string]string{"sdkId": client.ClientSdkID},
	}).Request()
	if err != nil {
		return err
	}

	return client.makeConfigureResponseRequest(request)
}

// ConfigureApplicationResponse configures the response for the application
func (client *Client) ConfigureApplicationResponse(responseConfig request.ResponseConfig) (err error) {
	requestEndpoint := "/apps/" + client.ClientSdkID + "/response-config"
	requestBody, err := client.marshalJSON(responseConfig)
	if err != nil {
		return err
	}

	request, err := (&yotirequest.SignedRequest{
		Key:        client.Key,
		HTTPMethod: "PUT",
		BaseURL:    client.getAPIURL(),
		Endpoint:   requestEndpoint,
		Headers:    yotirequest.JSONHeaders(),
		Body:       requestBody,
	}).Request()
	if err != nil {
		return err
	}

	return client.makeConfigureResponseRequest(request)
}
