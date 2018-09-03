package yoti

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/getyoti/yoti-go-sdk/yotiprotoattr_v3"
	"github.com/getyoti/yoti-go-sdk/yotiprotocom_v3"
	"github.com/golang/protobuf/proto"
)

const apiURL = "https://api.yoti.com/api/v1"
const sdkIdentifier = "Go"
const (
	authKeyHeader       = "X-Yoti-Auth-Key"
	authDigestHeader    = "X-Yoti-Auth-Digest"
	sdkIdentifierHeader = "X-Yoti-SDK"
)
const attributeAgeOver = "age_over:"
const attributeAgeUnder = "age_under:"

// Client represents a client that can communicate with yoti and return information about Yoti users.
type Client struct {
	// SdkID represents the SDK ID and NOT the App ID. This can be found in the integration section of your
	// application dashboard at https://www.yoti.com/dashboard/
	SdkID string

	// Key should be the security key given to you by yoti (see: security keys section of
	// https://www.yoti.com/dashboard/) for more information about how to load your key from a file see:
	// https://github.com/getyoti/yoti-go-sdk/blob/master/README.md
	Key []byte
}

// GetUserProfile requests information about a Yoti user using the one time use token generated by the Yoti login process.
//ActivityDetails represents the result of an activity between a user and the application
type ActivityDetails struct {
	UserProfile Profile
	// RememberMeID is a unique identifier Yoti assigns to your user, but only for your app
	// if the same user logs into your app again, you get the same id
	// if she/he logs into another application, Yoti will assign a different id for that app
	RememberMeID string
	// Base64Selfie is the selfie of the user encoded as a base64 URL
	Base64Selfie string
}

// It returns the outcome of the request. If the request was successful it will include the users details, otherwise
// it will specify a reason the request failed.
func (client *Client) GetUserProfile(token string) (UserProfile, error) {
	return getActivityDetails(doRequest, token, client.SdkID, client.Key)
}

func getActivityDetails(requester httpRequester, encryptedToken, sdkID string, keyBytes []byte) (result UserProfile, err error) {
	var key *rsa.PrivateKey
	var httpMethod = HTTPMethodGet

	if key, err = loadRsaKey(keyBytes); err != nil {
		err = fmt.Errorf("Invalid Key: %s", err.Error())
		return
	}

	// query parameters
	var token string
	if token, err = decryptToken(encryptedToken, key); err != nil {
		return
	}

	var nonce string
	if nonce, err = generateNonce(); err != nil {
		return
	}

	timestamp := getTimestamp()

	// create http endpoint
	endpoint := getProfileEndpoint(token, nonce, timestamp, sdkID)

	var headers map[string]string
	if headers, err = createHeaders(key, httpMethod, endpoint, nil); err != nil {
		return
	}

	var response *httpResponse
	if response, err = requester(apiURL+endpoint, headers, httpMethod, nil); err != nil {
		return
	}

	if response.Success {
		var parsedResponse = profileDO{}

		if err = json.Unmarshal([]byte(response.Content), &parsedResponse); err != nil {
			return
		}

		if parsedResponse.Receipt.SharingOutcome != "SUCCESS" {
			err = ErrSharingFailure
		} else {
			var attributeList *yotiprotoattr_v3.AttributeList
			if attributeList, err = decryptCurrentUserReceipt(&parsedResponse.Receipt, key); err != nil {
				return
			}

			id := parsedResponse.Receipt.RememberMeID

			result = UserProfile{
				ID:              id,
				OtherAttributes: make(map[string]AttributeValue)}

			if attributeList == nil {
				return
			}

			for _, attribute := range attributeList.Attributes {
				switch attribute.Name {
				case "selfie":

					switch attribute.ContentType {
					case yotiprotoattr_v3.ContentType_JPEG:
						result.Selfie = &Image{
							Type: ImageTypeJpeg,
							Data: attribute.Value}
					case yotiprotoattr_v3.ContentType_PNG:
						result.Selfie = &Image{
							Type: ImageTypePng,
							Data: attribute.Value}
					}
				case "given_names":
					result.GivenNames = string(attribute.Value)
				case "family_name":
					result.FamilyName = string(attribute.Value)
				case "full_name":
					result.FullName = string(attribute.Value)
				case "phone_number":
					result.MobileNumber = string(attribute.Value)
				case "email_address":
					result.EmailAddress = string(attribute.Value)
				case "date_of_birth":
					var parsedTime time.Time
					parsedTime, err = time.Parse("2006-01-02", string(attribute.Value))
					if err == nil {
						result.DateOfBirth = &parsedTime
					} else {
						log.Printf("Unable to parse `date_of_birth` value: %q. Error: %q", attribute.Value, err)
					}
				case "postal_address":
					result.Address = string(attribute.Value)
				case "structured_postal_address":
					result.StructuredPostalAddress, err = unmarshallJSON(attribute.Value)
				case "gender":
					result.Gender = string(attribute.Value)
				case "nationality":
					result.Nationality = string(attribute.Value)
				default:
					if strings.HasPrefix(attribute.Name, attributeAgeOver) ||
						strings.HasPrefix(attribute.Name, attributeAgeUnder) {

						var isAgeVerified *bool
						isAgeVerified, err = parseIsAgeVerifiedValue(attribute.Value)

						if err == nil {
							result.IsAgeVerified = isAgeVerified
						} else {
							log.Printf("Unable to parse `IsAgeVerified` value: %q. Error: %q", attribute.Value, err)
						}
					}

					switch attribute.ContentType {
					case yotiprotoattr_v3.ContentType_DATE:
						result.OtherAttributes[attribute.Name] = AttributeValue{
							Type:  AttributeTypeDate,
							Value: attribute.Value}
					case yotiprotoattr_v3.ContentType_STRING:
						result.OtherAttributes[attribute.Name] = AttributeValue{
							Type:  AttributeTypeText,
							Value: attribute.Value}
					case yotiprotoattr_v3.ContentType_JPEG:
						result.OtherAttributes[attribute.Name] = AttributeValue{
							Type:  AttributeTypeJPEG,
							Value: attribute.Value}
					case yotiprotoattr_v3.ContentType_PNG:
						result.OtherAttributes[attribute.Name] = AttributeValue{
							Type:  AttributeTypePNG,
							Value: attribute.Value}
					case yotiprotoattr_v3.ContentType_JSON:
						result.OtherAttributes[attribute.Name] = AttributeValue{
							Type:  AttributeTypeJSON,
							Value: attribute.Value}
					}
				}
			}
			var formattedAddress string
			formattedAddress, err = getFormattedAddressIfAddressIsMissing(result)
			if err != nil {
				log.Printf("Unable to get 'Formatted Address' from 'Structured Postal Address'. Error: %q", err)
			} else if formattedAddress != "" {
				result.Address = formattedAddress
			}
		}
	} else {
		switch response.StatusCode {
		case http.StatusNotFound:
			err = ErrProfileNotFound
		default:
			err = ErrFailure
		}
	}

	return
}

func getFormattedAddressIfAddressIsMissing(result UserProfile) (address string, err error) {
	if result.Address == "" && result.StructuredPostalAddress != nil {
		var formattedAddress string
		formattedAddress, err = retrieveFormattedAddressFromStructuredPostalAddress(result.StructuredPostalAddress)
		if err == nil {
			return formattedAddress, nil
		}
	}

	return "", err
}

func retrieveFormattedAddressFromStructuredPostalAddress(structuredPostalAddress interface{}) (address string, err error) {
	parsedStructuredAddressInterfaceArray := structuredPostalAddress.([]interface{})
	parsedStructuredAddressMap := parsedStructuredAddressInterfaceArray[0].(map[string]interface{})
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

func unmarshallJSON(byteValue []byte) (result interface{}, err error) {
	var unmarshalledJSON interface{}
	err = json.Unmarshal(byteValue, &unmarshalledJSON)

	if err != nil {
		return nil, err
	}

	return unmarshalledJSON, err
}

func decryptCurrentUserReceipt(receipt *receiptDO, key *rsa.PrivateKey) (result *yotiprotoattr_v3.AttributeList, err error) {
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

	encryptedData := &yotiprotocom_v3.EncryptedData{}
	if err = proto.Unmarshal(otherPartyProfileContentBytes, encryptedData); err != nil {
		return nil, err
	}

	var decipheredBytes []byte
	if decipheredBytes, err = decipherAes(unwrappedKey, encryptedData.Iv, encryptedData.CipherText); err != nil {
		return nil, err
	}

	attributeList := &yotiprotoattr_v3.AttributeList{}
	if err := proto.Unmarshal(decipheredBytes, attributeList); err != nil {
		return nil, err
	}

	return attributeList, nil
}

// PerformAmlCheck performs an Anti Money Laundering Check (AML) for a particular user.
// Returns three boolean values: 'OnPEPList', 'OnWatchList' and 'OnFraudList'.
func (client *Client) PerformAmlCheck(amlProfile AmlProfile) (AmlResult, error) {
	return performAmlCheck(amlProfile, doRequest, client.SdkID, client.Key)
}

func performAmlCheck(amlProfile AmlProfile, requester httpRequester, sdkID string, keyBytes []byte) (result AmlResult, err error) {
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

	timestamp := getTimestamp()
	endpoint := getAMLEndpoint(nonce, timestamp, sdkID)

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
		result, err = GetAmlResultFromResponse([]byte(response.Content))
		return
	}

	err = fmt.Errorf(
		"AML Check was unsuccessful, status code: '%d', content:'%s'", response.StatusCode, response.Content)

	return
}

func getAuthKey(key *rsa.PrivateKey) (string, error) {
	return getDerEncodedPublicKey(key)
}

func getProfileEndpoint(token, nonce, timestamp, sdkID string) string {
	return fmt.Sprintf("/profile/%s?nonce=%s&timestamp=%s&appId=%s", token, nonce, timestamp, sdkID)
}

func getAMLEndpoint(nonce, timestamp, sdkID string) string {
	return fmt.Sprintf("/aml-check?appId=%s&timestamp=%s&nonce=%s", sdkID, timestamp, nonce)
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

func getTimestamp() string {
	return strconv.FormatInt(time.Now().Unix()*1000, 10)
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

	return headers, err
}

func decryptToken(encryptedConnectToken string, key *rsa.PrivateKey) (result string, err error) {
	// token was encoded as a urlsafe base64 so it can be transfered in a url
	var cipherBytes []byte
	if cipherBytes, err = urlSafeBase64ToBytes(encryptedConnectToken); err != nil {
		return
	}

	var decipheredBytes []byte
	if decipheredBytes, err = decryptRsa(cipherBytes, key); err != nil {
		return
	}

	result = bytesToUtf8(decipheredBytes)
	return
}

func unwrapKey(wrappedKey string, key *rsa.PrivateKey) (result []byte, err error) {
	var cipherBytes []byte
	if cipherBytes, err = base64ToBytes(wrappedKey); err != nil {
		return
	}
	result, err = decryptRsa(cipherBytes, key)
	return
}
