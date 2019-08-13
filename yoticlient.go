package yoti

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/getyoti/yoti-go-sdk/v2/attribute"
	"github.com/getyoti/yoti-go-sdk/v2/yotiprotoattr"
	"github.com/getyoti/yoti-go-sdk/v2/yotiprotocom"
	"github.com/golang/protobuf/proto"
)

const (
	apiDefaultURL        = "https://api.yoti.com/api/v1"
	sdkIdentifier        = "Go"
	sdkVersionIdentifier = "2.5.0"

	authKeyHeader              = "X-Yoti-Auth-Key"
	authDigestHeader           = "X-Yoti-Auth-Digest"
	sdkIdentifierHeader        = "X-Yoti-SDK"
	sdkVersionIdentifierHeader = sdkIdentifierHeader + "-Version"
	attributeAgeOver           = "age_over:"
	attributeAgeUnder          = "age_under:"

	defaultUnknownErrorMessageConst = "Unknown HTTP Error: %[1]d: %[2]s"
)

var (
	// DefaultHTTPErrorMessages maps HTTP error status codes to format strings
	// to create useful error messages. -1 is used to specify a default message
	// that can be used if an error code is not explicitly defined
	DefaultHTTPErrorMessages = map[int]string{
		-1: defaultUnknownErrorMessageConst,
	}
)

// ClientInterface defines the interface required to Mock the YotiClient for
// testing
type clientInterface interface {
	makeRequest(string, string, []byte, ...map[int]string) (string, error)
	GetSdkID() string
}

// Client represents a client that can communicate with yoti and return information about Yoti users.
type Client struct {
	// SdkID represents the SDK ID and NOT the App ID. This can be found in the integration section of your
	// application hub at https://hub.yoti.com/
	SdkID string

	// Key should be the security key given to you by yoti (see: security keys section of
	// https://hub.yoti.com) for more information about how to load your key from a file see:
	// https://github.com/getyoti/yoti-go-sdk/blob/master/README.md
	Key []byte

	apiURL string
}

// OverrideAPIURL overrides the default API URL for this Yoti Client to permit
// testing
func (client *Client) OverrideAPIURL(apiURL string) {
	client.apiURL = apiURL
}

// Deprecated: Will be removed in v3.0.0. Use `GetActivityDetails` instead. GetUserProfile requests information about a Yoti user using the one time use token generated by the Yoti login process.
// It returns the outcome of the request. If the request was successful it will include the users details, otherwise
// it will specify a reason the request failed.
func (client *Client) GetUserProfile(token string) (userProfile UserProfile, firstError error) {
	var errStrings []string
	userProfile, _, errStrings = getActivityDetails(doRequest, token, client.SdkID, client.Key, client.getAPIURL())
	if len(errStrings) > 0 {
		firstError = errors.New(errStrings[0])
	}
	return userProfile, firstError
}

func (client *Client) getAPIURL() string {
	if client.apiURL != "" {
		return client.apiURL
	}
	return apiDefaultURL
}

// GetSdkID gets the Client SDK ID attached to this client instance
func (client *Client) GetSdkID() string {
	return client.SdkID
}

// GetActivityDetails requests information about a Yoti user using the one time use token generated by the Yoti login process.
// It returns the outcome of the request. If the request was successful it will include the users details, otherwise
// it will specify a reason the request failed.
func (client *Client) GetActivityDetails(token string) (ActivityDetails, []string) {
	_, activityDetails, errStrings := getActivityDetails(doRequest, token, client.SdkID, client.Key, client.getAPIURL())
	return activityDetails, errStrings
}

func handleHTTPError(response *httpResponse, errorMessages ...map[int]string) error {
	for _, handler := range errorMessages {
		for code, message := range handler {
			if code == response.StatusCode {
				return fmt.Errorf(
					message,
					response.StatusCode,
					response.Content,
				)
			}

		}
		if defaultMessage, ok := handler[-1]; ok {
			return fmt.Errorf(
				defaultMessage,
				response.StatusCode,
				response.Content,
			)
		}

	}
	return fmt.Errorf(
		defaultUnknownErrorMessageConst,
		response.StatusCode,
		response.Content,
	)
}

// MakeRequest is used by other yoti Packages to make requests using a single
// common client object. Users should not use this function directly
func (client *Client) makeRequest(httpMethod, endpoint string, payload []byte, httpErrorMessages ...map[int]string) (responseData string, err error) {
	key, err := loadRsaKey(client.Key)
	if err != nil {
		return
	}

	headers, err := createHeaders(key, httpMethod, endpoint, payload)
	if err != nil {
		return
	}

	var response *httpResponse
	if response, err = doRequest(client.apiURL+endpoint, headers, httpMethod, payload); err != nil {
		return
	}

	if response.Success {
		responseData = response.Content
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		err = handleHTTPError(response, httpErrorMessages...)
		return
	}
	return
}

func getActivityDetails(requester httpRequester, encryptedToken, sdkID string, keyBytes []byte, apiURL string) (userProfile UserProfile, activityDetails ActivityDetails, errStrings []string) {
	var err error
	var key *rsa.PrivateKey
	var httpMethod = HTTPMethodGet

	if key, err = loadRsaKey(keyBytes); err != nil {
		errStrings = append(errStrings, fmt.Sprintf("Invalid Key: %s", err.Error()))
		return
	}

	// query parameters
	var token string
	if token, err = decryptToken(encryptedToken, key); err != nil {
		errStrings = append(errStrings, err.Error())
		return
	}

	var nonce string
	if nonce, err = generateNonce(); err != nil {
		errStrings = append(errStrings, err.Error())
		return
	}

	// create http endpoint
	endpoint := getProfileEndpoint(token, nonce, sdkID)

	var headers map[string]string
	if headers, err = createHeaders(key, httpMethod, endpoint, nil); err != nil {
		errStrings = append(errStrings, err.Error())
		return
	}

	var response *httpResponse
	if response, err = requester(apiURL+endpoint, headers, httpMethod, nil); err != nil {
		errStrings = append(errStrings, err.Error())
		return
	}

	if response.Success {
		return handleSuccessfulResponse(response.Content, key)
	}

	switch response.StatusCode {
	case http.StatusNotFound:
		err = ErrProfileNotFound
	default:
		err = ErrFailure
	}

	if err != nil {
		errStrings = append(errStrings, err.Error())
	}

	return userProfile, activityDetails, errStrings
}

func getProtobufAttribute(profile Profile, key string) *yotiprotoattr.Attribute {
	for _, v := range profile.attributeSlice {
		if v.Name == AttrConstStructuredPostalAddress {
			return v
		}
	}

	return nil
}

func handleSuccessfulResponse(responseContent string, key *rsa.PrivateKey) (userProfile UserProfile, activityDetails ActivityDetails, errStrings []string) {
	var parsedResponse = profileDO{}
	var err error

	if err = json.Unmarshal([]byte(responseContent), &parsedResponse); err != nil {
		errStrings = append(errStrings, err.Error())
		return
	}

	if parsedResponse.Receipt.SharingOutcome != "SUCCESS" {
		err = ErrSharingFailure
		errStrings = append(errStrings, err.Error())
	} else {
		var attributeList, appAttributeList *yotiprotoattr.AttributeList
		if attributeList, err = decryptCurrentUserReceipt(&parsedResponse.Receipt, key); err != nil {
			errStrings = append(errStrings, err.Error())
			return
		}
		if appAttributeList, err = decryptCurrentApplicationProfile(&parsedResponse.Receipt, key); err != nil {
			errStrings = append(errStrings, err.Error())
			return
		}
		id := parsedResponse.Receipt.RememberMeID

		userProfile = addAttributesToUserProfile(id, attributeList) //deprecated: will be removed in v3.0.0

		profile := Profile{
			baseProfile{
				attributeSlice: createAttributeSlice(attributeList),
			},
		}
		appProfile := ApplicationProfile{
			baseProfile{
				attributeSlice: createAttributeSlice(appAttributeList),
			},
		}

		var formattedAddress string
		formattedAddress, err = ensureAddressProfile(profile)
		if err != nil {
			log.Printf("Unable to get 'Formatted Address' from 'Structured Postal Address'. Error: %q", err)
		} else if formattedAddress != "" {
			if _, err = profile.StructuredPostalAddress(); err != nil {
				errStrings = append(errStrings, err.Error())
				return
			}

			protoStructuredPostalAddress := getProtobufAttribute(profile, AttrConstStructuredPostalAddress)

			addressAttribute := &yotiprotoattr.Attribute{
				Name:        AttrConstAddress,
				Value:       []byte(formattedAddress),
				ContentType: yotiprotoattr.ContentType_STRING,
				Anchors:     protoStructuredPostalAddress.Anchors,
			}

			profile.attributeSlice = append(profile.attributeSlice, addressAttribute)
		}

		activityDetails = ActivityDetails{
			UserProfile:        profile,
			rememberMeID:       id,
			parentRememberMeID: parsedResponse.Receipt.ParentRememberMeID,
			timestamp:          parsedResponse.Receipt.Timestamp,
			receiptID:          parsedResponse.Receipt.ReceiptID,
			ApplicationProfile: appProfile,
		}
	}

	return userProfile, activityDetails, errStrings
}

func addAttributesToUserProfile(id string, attributeList *yotiprotoattr.AttributeList) (result UserProfile) {
	result = UserProfile{
		ID:              id,
		OtherAttributes: make(map[string]AttributeValue)}

	if attributeList == nil {
		return
	}

	for _, a := range attributeList.Attributes {
		switch a.Name {
		case "selfie":

			switch a.ContentType {
			case yotiprotoattr.ContentType_JPEG:
				result.Selfie = &Image{
					Type: ImageTypeJpeg,
					Data: a.Value}
			case yotiprotoattr.ContentType_PNG:
				result.Selfie = &Image{
					Type: ImageTypePng,
					Data: a.Value}
			}
		case "given_names":
			result.GivenNames = string(a.Value)
		case "family_name":
			result.FamilyName = string(a.Value)
		case "full_name":
			result.FullName = string(a.Value)
		case "phone_number":
			result.MobileNumber = string(a.Value)
		case "email_address":
			result.EmailAddress = string(a.Value)
		case "date_of_birth":
			parsedTime, err := time.Parse("2006-01-02", string(a.Value))
			if err == nil {
				result.DateOfBirth = &parsedTime
			} else {
				log.Printf("Unable to parse `date_of_birth` value: %q. Error: %q", a.Value, err)
			}
		case "postal_address":
			result.Address = string(a.Value)
		case "structured_postal_address":
			structuredPostalAddress, err := attribute.UnmarshallJSON(a.Value)

			if err == nil {
				result.StructuredPostalAddress = structuredPostalAddress
			} else {
				log.Printf("Unable to parse `structured_postal_address` value: %q. Error: %q", a.Value, err)
			}
		case "gender":
			result.Gender = string(a.Value)
		case "nationality":
			result.Nationality = string(a.Value)
		default:
			if strings.HasPrefix(a.Name, attributeAgeOver) ||
				strings.HasPrefix(a.Name, attributeAgeUnder) {

				isAgeVerified, err := parseIsAgeVerifiedValue(a.Value)

				if err == nil {
					result.IsAgeVerified = isAgeVerified
				} else {
					log.Printf("Unable to parse `IsAgeVerified` value: %q. Error: %q", a.Value, err)
				}
			}

			switch a.ContentType {
			case yotiprotoattr.ContentType_DATE:
				result.OtherAttributes[a.Name] = AttributeValue{
					Type:  AttributeTypeDate,
					Value: a.Value}
			case yotiprotoattr.ContentType_STRING:
				result.OtherAttributes[a.Name] = AttributeValue{
					Type:  AttributeTypeText,
					Value: a.Value}
			case yotiprotoattr.ContentType_JPEG:
				result.OtherAttributes[a.Name] = AttributeValue{
					Type:  AttributeTypeJPEG,
					Value: a.Value}
			case yotiprotoattr.ContentType_PNG:
				result.OtherAttributes[a.Name] = AttributeValue{
					Type:  AttributeTypePNG,
					Value: a.Value}
			case yotiprotoattr.ContentType_JSON:
				result.OtherAttributes[a.Name] = AttributeValue{
					Type:  AttributeTypeJSON,
					Value: a.Value}
			}
		}
	}
	formattedAddress, err := ensureAddressUserProfile(result)
	if err != nil {
		log.Printf("Unable to get 'Formatted Address' from 'Structured Postal Address'. Error: %q", err)
	} else if formattedAddress != "" {
		result.Address = formattedAddress
	}

	return
}

func createAttributeSlice(protoAttributeList *yotiprotoattr.AttributeList) (result []*yotiprotoattr.Attribute) {
	if protoAttributeList != nil {
		result = append(result, protoAttributeList.Attributes...)
	}

	return result
}

func ensureAddressUserProfile(result UserProfile) (address string, err error) {
	if result.Address == "" && result.StructuredPostalAddress != nil {
		var formattedAddress string
		formattedAddress, err = retrieveFormattedAddressFromStructuredPostalAddress(result.StructuredPostalAddress)
		if err == nil {
			return formattedAddress, nil
		}
	}

	return "", err
}

func ensureAddressProfile(profile Profile) (address string, err error) {
	if profile.Address() == nil {
		var structuredPostalAddress *attribute.JSONAttribute
		if structuredPostalAddress, err = profile.StructuredPostalAddress(); err == nil {
			if (structuredPostalAddress != nil && !reflect.DeepEqual(structuredPostalAddress, attribute.JSONAttribute{})) {
				var formattedAddress string
				formattedAddress, err = retrieveFormattedAddressFromStructuredPostalAddress(structuredPostalAddress.Value())
				if err == nil {
					return formattedAddress, nil
				}
			}
		}
	}

	return "", err
}

func retrieveFormattedAddressFromStructuredPostalAddress(structuredPostalAddress interface{}) (address string, err error) {
	parsedStructuredAddressMap := structuredPostalAddress.(map[string]interface{})
	if formattedAddress, ok := parsedStructuredAddressMap["formatted_address"]; ok {
		return formattedAddress.(string), nil
	}
	return
}

func parseIsAgeVerifiedValue(byteValue []byte) (result *bool, err error) {
	stringValue := string(byteValue)

	var parseResult bool
	parseResult, err = strconv.ParseBool(stringValue)

	if err != nil {
		return nil, err
	}

	result = &parseResult

	return
}
func decryptCurrentApplicationProfile(receipt *receiptDO, key *rsa.PrivateKey) (result *yotiprotoattr.AttributeList, err error) {
	var unwrappedKey []byte
	if unwrappedKey, err = unwrapKey(receipt.WrappedReceiptKey, key); err != nil {
		return
	}

	if receipt.ProfileContent == "" {
		return
	}

	var profileContentBytes []byte
	if profileContentBytes, err = base64ToBytes(receipt.ProfileContent); err != nil {
		return
	}

	encryptedData := &yotiprotocom.EncryptedData{}
	if err = proto.Unmarshal(profileContentBytes, encryptedData); err != nil {
		return nil, err
	}

	var decipheredBytes []byte
	if decipheredBytes, err = decipherAes(unwrappedKey, encryptedData.Iv, encryptedData.CipherText); err != nil {
		return nil, err
	}

	attributeList := &yotiprotoattr.AttributeList{}
	if err := proto.Unmarshal(decipheredBytes, attributeList); err != nil {
		return nil, err
	}

	return attributeList, nil
}

func decryptCurrentUserReceipt(receipt *receiptDO, key *rsa.PrivateKey) (result *yotiprotoattr.AttributeList, err error) {
	var unwrappedKey []byte
	if unwrappedKey, err = unwrapKey(receipt.WrappedReceiptKey, key); err != nil {
		return
	}

	if receipt.OtherPartyProfileContent == "" {
		return
	}

	var otherPartyProfileContentBytes []byte
	if otherPartyProfileContentBytes, err = base64ToBytes(receipt.OtherPartyProfileContent); err != nil {
		return
	}

	encryptedData := &yotiprotocom.EncryptedData{}
	if err = proto.Unmarshal(otherPartyProfileContentBytes, encryptedData); err != nil {
		return nil, err
	}

	var decipheredBytes []byte
	if decipheredBytes, err = decipherAes(unwrappedKey, encryptedData.Iv, encryptedData.CipherText); err != nil {
		return nil, err
	}

	attributeList := &yotiprotoattr.AttributeList{}
	if err := proto.Unmarshal(decipheredBytes, attributeList); err != nil {
		return nil, err
	}

	return attributeList, nil
}

// PerformAmlCheck performs an Anti Money Laundering Check (AML) for a particular user.
// Returns three boolean values: 'OnPEPList', 'OnWatchList' and 'OnFraudList'.
func (client *Client) PerformAmlCheck(amlProfile AmlProfile) (AmlResult, error) {
	return performAmlCheck(amlProfile, doRequest, client.SdkID, client.Key, client.getAPIURL())
}

func performAmlCheck(amlProfile AmlProfile, requester httpRequester, sdkID string, keyBytes []byte, apiURL string) (result AmlResult, err error) {
	var key *rsa.PrivateKey
	var httpMethod = HTTPMethodPost

	if key, err = loadRsaKey(keyBytes); err != nil {
		err = fmt.Errorf("Invalid Key: %s", err.Error())
		return
	}

	var nonce string
	if nonce, err = generateNonce(); err != nil {
		return
	}

	endpoint := getAMLEndpoint(nonce, sdkID)

	var content []byte
	if content, err = json.Marshal(amlProfile); err != nil {
		return
	}

	var headers map[string]string
	if headers, err = createHeaders(key, httpMethod, endpoint, content); err != nil {
		return
	}

	var response *httpResponse
	if response, err = requester(apiURL+endpoint, headers, httpMethod, content); err != nil {
		return
	}

	if response.Success {
		result, err = GetAmlResult([]byte(response.Content))
		return
	}

	err = fmt.Errorf(
		"AML Check was unsuccessful, status code: '%d', content:'%s'", response.StatusCode, response.Content)

	return
}

func getAuthDigest(endpoint string, key *rsa.PrivateKey, httpMethod string, content []byte) (result string, err error) {
	digest := httpMethod + "&" + endpoint

	if content != nil {
		digest += "&" + bytesToBase64(content)
	}

	digestBytes := utfToBytes(digest)
	var signedDigestBytes []byte

	if signedDigestBytes, err = signDigest(digestBytes, key); err != nil {
		return
	}

	result = bytesToBase64(signedDigestBytes)
	return
}

func createHeaders(key *rsa.PrivateKey, httpMethod string, endpoint string, content []byte) (headers map[string]string, err error) {
	var authKey string
	if authKey, err = getAuthKey(key); err != nil {
		return
	}

	var authDigest string
	if authDigest, err = getAuthDigest(endpoint, key, httpMethod, content); err != nil {
		return
	}

	headers = make(map[string]string)

	headers[authKeyHeader] = authKey
	headers[authDigestHeader] = authDigest
	headers[sdkIdentifierHeader] = sdkIdentifier
	headers[sdkVersionIdentifierHeader] = sdkIdentifier + "-" + sdkVersionIdentifier

	return headers, err
}
