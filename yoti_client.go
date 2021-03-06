package yoti

import (
	"crypto/rsa"
	"os"

	"github.com/getyoti/yoti-go-sdk/v3/requests"

	"github.com/getyoti/yoti-go-sdk/v3/aml"
	"github.com/getyoti/yoti-go-sdk/v3/cryptoutil"
	"github.com/getyoti/yoti-go-sdk/v3/dynamic"
	"github.com/getyoti/yoti-go-sdk/v3/profile"
)

const apiDefaultURL = "https://api.yoti.com/api/v1"

// Client represents a client that can communicate with yoti and return information about Yoti users.
type Client struct {
	// SdkID represents the SDK ID and NOT the App ID. This can be found in the integration section of your
	// application hub at https://hub.yoti.com/
	SdkID string

	// Key should be the security key given to you by yoti (see: security keys section of
	// https://hub.yoti.com) for more information about how to load your key from a file see:
	// https://github.com/getyoti/yoti-go-sdk/blob/master/README.md
	Key *rsa.PrivateKey

	apiURL     string
	HTTPClient requests.HttpClient // Mockable HTTP Client Interface
}

// NewClient constructs a Client object
func NewClient(sdkID string, key []byte) (*Client, error) {
	decodedKey, err := cryptoutil.ParseRSAKey(key)

	if err != nil {
		return nil, err
	}

	return &Client{
		SdkID: sdkID,
		Key:   decodedKey,
	}, err
}

// OverrideAPIURL overrides the default API URL for this Yoti Client
func (client *Client) OverrideAPIURL(apiURL string) {
	client.apiURL = apiURL
}

func (client *Client) getAPIURL() string {
	if client.apiURL != "" {
		return client.apiURL
	}

	if value, exists := os.LookupEnv("YOTI_API_URL"); exists && value != "" {
		return value
	}

	return apiDefaultURL
}

// GetSdkID gets the Client SDK ID attached to this client instance
func (client *Client) GetSdkID() string {
	return client.SdkID
}

// GetActivityDetails requests information about a Yoti user using the one time
// use token generated by the Yoti login process. It returns the outcome of the
// request. If the request was successful it will include the user's details,
// otherwise an error will be returned, which will specify the reason the
// request failed. If the function call can be reattempted with the same token
// the error will implement interface{ Temporary() bool }.
func (client *Client) GetActivityDetails(token string) (activity profile.ActivityDetails, err error) {
	return profile.GetActivityDetails(client.HTTPClient, token, client.GetSdkID(), client.getAPIURL(), client.Key)
}

// PerformAmlCheck performs an Anti Money Laundering Check (AML) for a particular user.
// Returns three boolean values: 'OnPEPList', 'OnWatchList' and 'OnFraudList'.
func (client *Client) PerformAmlCheck(profile aml.Profile) (result aml.Result, err error) {
	return aml.PerformCheck(client.HTTPClient, profile, client.GetSdkID(), client.getAPIURL(), client.Key)
}

// CreateShareURL creates a QR code for a specified dynamic scenario
func (client *Client) CreateShareURL(scenario *dynamic.Scenario) (share dynamic.ShareURL, err error) {
	return dynamic.CreateShareURL(client.HTTPClient, scenario, client.GetSdkID(), client.getAPIURL(), client.Key)
}
