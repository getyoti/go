package yoti

import (
	"encoding/base64"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/getyoti/yoti-go-sdk/v2/anchor"
	"github.com/getyoti/yoti-go-sdk/v2/attribute"
	"github.com/getyoti/yoti-go-sdk/v2/yotiprotoattr"
	"github.com/golang/protobuf/proto"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

const (
	token             = "NpdmVVGC-28356678-c236-4518-9de4-7a93009ccaf0-c5f92f2a-5539-453e-babc-9b06e1d6b7de"
	encryptedToken    = "b6H19bUCJhwh6WqQX_sEHWX9RP-A_ANr1fkApwA4Dp2nJQFAjrF9e6YCXhNBpAIhfHnN0iXubyXxXZMNwNMSQ5VOxkqiytrvPykfKQWHC6ypSbfy0ex8ihndaAXG5FUF-qcU8QaFPMy6iF3x0cxnY0Ij0kZj0Ng2t6oiNafb7AhT-VGXxbFbtZu1QF744PpWMuH0LVyBsAa5N5GJw2AyBrnOh67fWMFDKTJRziP5qCW2k4h5vJfiYr_EOiWKCB1d_zINmUm94ZffGXxcDAkq-KxhN1ZuNhGlJ2fKcFh7KxV0BqlUWPsIEiwS0r9CJ2o1VLbEs2U_hCEXaqseEV7L29EnNIinEPVbL4WR7vkF6zQCbK_cehlk2Qwda-VIATqupRO5grKZN78R9lBitvgilDaoE7JB_VFcPoljGQ48kX0wje1mviX4oJHhuO8GdFITS5LTbojGVQWT7LUNgAUe0W0j-FLHYYck3v84OhWTqads5_jmnnLkp9bdJSRuJF0e8pNdePnn2lgF-GIcyW_0kyGVqeXZrIoxnObLpF-YeUteRBKTkSGFcy7a_V_DLiJMPmH8UXDLOyv8TVt3ppzqpyUrLN2JVMbL5wZ4oriL2INEQKvw_boDJjZDGeRlu5m1y7vGDNBRDo64-uQM9fRUULPw-YkABNwC0DeShswzT00="
	wrappedReceiptKey = "kyHPjq2+Y48cx+9yS/XzmW09jVUylSdhbP+3Q9Tc9p6bCEnyfa8vj38AIu744RzzE+Dc4qkSF21VfzQKtJVILfOXu5xRc7MYa5k3zWhjiesg/gsrv7J4wDyyBpHIJB8TWXnubYMbSYQJjlsfwyxE9kGe0YI08pRo2Tiht0bfR5Z/YrhAk4UBvjp84D+oyug/1mtGhKphA4vgPhQ9/y2wcInYxju7Q6yzOsXGaRUXR38Tn2YmY9OBgjxiTnhoYJFP1X9YJkHeWMW0vxF1RHxgIVrpf7oRzdY1nq28qzRg5+wC7cjRpS2i/CKUAo0oVG4pbpXsaFhaTewStVC7UFtA77JHb3EnF4HcSWMnK5FM7GGkL9MMXQenh11NZHKPWXpux0nLZ6/vwffXZfsiyTIcFL/NajGN8C/hnNBljoQ+B3fzWbjcq5ueUOPwARZ1y38W83UwMynzkud/iEdHLaZIu4qUCRkfSxJg7Dc+O9/BdiffkOn2GyFmNjVeq754DCUypxzMkjYxokedN84nK13OU4afVyC7t5DDxAK/MqAc69NCBRLqMi5f8BMeOZfMcSWPGC9a2Qu8VgG125TuZT4+wIykUhGyj3Bb2/fdPsxwuKFR+E0uqs0ZKvcv1tkNRRtKYBqTacgGK9Yoehg12cyLrITLdjU1fmIDn4/vrhztN5w="
	attributeName     = "test_attribute_name"
)

type mockHTTPClient struct {
	do func(*http.Request) (*http.Response, error)
}

func (mock *mockHTTPClient) Do(request *http.Request) (*http.Response, error) {
	if mock.do != nil {
		return mock.do(request)
	}
	return nil, nil
}

func TestYotiClient_KeyLoad_Failure(t *testing.T) {
	key, _ := ioutil.ReadFile("test-key-invalid-format.pem")

	client := Client{
		Key: key,
		httpClient: &mockHTTPClient{
			do: func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: 500,
				}, nil
			},
		},
	}

	_, _, errorStrings := client.getActivityDetails(encryptedToken)

	assert.Assert(t, len(errorStrings) > 0)
	assert.Check(t, strings.HasPrefix(errorStrings[0], "Invalid Key"))
}

func TestYotiClient_HttpFailure_ReturnsFailure(t *testing.T) {
	key, _ := ioutil.ReadFile("test-key.pem")

	client := Client{
		Key: key,
		httpClient: &mockHTTPClient{
			do: func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: 500,
				}, nil
			},
		},
	}

	_, _, errorStrings := client.getActivityDetails(encryptedToken)

	assert.Assert(t, len(errorStrings) > 0)
	assert.Check(t, strings.HasPrefix(errorStrings[0], "Unknown HTTP Error"))
}

func TestYotiClient_HttpFailure_ReturnsProfileNotFound(t *testing.T) {
	key, _ := ioutil.ReadFile("test-key.pem")

	client := Client{
		Key: key,
		httpClient: &mockHTTPClient{
			do: func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: 404,
				}, nil
			},
		},
	}

	_, _, errorStrings := client.getActivityDetails(encryptedToken)

	assert.Assert(t, len(errorStrings) > 0)
	assert.Check(t, strings.HasPrefix(errorStrings[0], "Profile Not Found"))
}

func TestYotiClient_SharingFailure_ReturnsFailure(t *testing.T) {
	key, _ := ioutil.ReadFile("test-key.pem")

	client := Client{
		Key: key,
		httpClient: &mockHTTPClient{
			do: func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: 200,
					Body:       ioutil.NopCloser(strings.NewReader(`{"session_data":"session_data","receipt":{"receipt_id": null,"other_party_profile_content": null,"policy_uri":null,"personal_key":null,"remember_me_id":null, "sharing_outcome":"FAILURE","timestamp":"2016-09-23T13:04:11Z"}}`)),
				}, nil
			},
		},
	}

	_, _, errorStrings := client.getActivityDetails(encryptedToken)

	assert.Assert(t, len(errorStrings) > 0)
	assert.Check(t, strings.HasPrefix(errorStrings[0], ErrSharingFailure.Error()))
}

func TestYotiClient_TokenDecodedSuccessfully(t *testing.T) {
	key, _ := ioutil.ReadFile("test-key.pem")

	expectedAbsoluteURL := "/api/v1/profile/" + token

	client := Client{
		Key: key,
		httpClient: &mockHTTPClient{
			do: func(request *http.Request) (*http.Response, error) {
				parsed, err := url.Parse(request.URL.String())
				assert.Assert(t, is.Nil(err), "Yoti API did not generate a valid URI.")
				assert.Equal(t, parsed.Path, expectedAbsoluteURL, "Yoti API did not generate a valid URL path.")

				return &http.Response{
					StatusCode: 500,
				}, nil
			},
		},
	}

	_, _, errorStrings := client.getActivityDetails(encryptedToken)

	assert.Assert(t, len(errorStrings) > 0)
	assert.Check(t, strings.HasPrefix(errorStrings[0], "Unknown HTTP Error"))
}

func TestYotiClient_ParseProfile_Success(t *testing.T) {
	key, _ := ioutil.ReadFile("test-key.pem")

	otherPartyProfileContent := "ChCZAib1TBm9Q5GYfFrS1ep9EnAwQB5shpAPWLBgZgFgt6bCG3S5qmZHhrqUbQr3yL6yeLIDwbM7x4nuT/MYp+LDXgmFTLQNYbDTzrEzqNuO2ZPn9Kpg+xpbm9XtP7ZLw3Ep2BCmSqtnll/OdxAqLb4DTN4/wWdrjnFC+L/oQEECu646"
	rememberMeID := "remember_me_id0123456789"

	client := Client{
		Key: key,
		httpClient: &mockHTTPClient{
			do: func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: 200,
					Body:       ioutil.NopCloser(strings.NewReader(`{"receipt":{"wrapped_receipt_key": "` + wrappedReceiptKey + `","other_party_profile_content": "` + otherPartyProfileContent + `","remember_me_id":"` + rememberMeID + `", "sharing_outcome":"SUCCESS"}}`)),
				}, nil
			},
		},
	}

	userProfile, activityDetails, errorStrings := client.getActivityDetails(encryptedToken)

	assert.Assert(t, is.Nil(errorStrings))
	assert.Equal(t, userProfile.ID, rememberMeID)

	assert.Assert(t, userProfile.Selfie != nil)
	assert.Equal(t, string(userProfile.Selfie.Data), "selfie0123456789")
	assert.Equal(t, userProfile.MobileNumber, "phone_number0123456789")

	dobUserProfile := time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)
	assert.Assert(t, userProfile.DateOfBirth.Equal(dobUserProfile))

	profile := activityDetails.UserProfile

	assert.Equal(t, activityDetails.RememberMeID(), rememberMeID)

	expectedSelfieValue := "selfie0123456789"

	assert.Assert(t, profile.Selfie() != nil)
	assert.DeepEqual(t, profile.Selfie().Value().Data, []byte(expectedSelfieValue))
	assert.Equal(t, profile.MobileNumber().Value(), "phone_number0123456789")

	expectedDoB := time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)

	actualDoB, err := profile.DateOfBirth()
	assert.Assert(t, is.Nil(err))

	assert.Assert(t, actualDoB != nil)
	assert.DeepEqual(t, actualDoB.Value(), &expectedDoB)
}

func TestYotiClient_ParentRememberMeID(t *testing.T) {
	key, _ := ioutil.ReadFile("test-key.pem")
	otherPartyProfileContent := "ChCZAib1TBm9Q5GYfFrS1ep9EnAwQB5shpAPWLBgZgFgt6bCG3S5qmZHhrqUbQr3yL6yeLIDwbM7x4nuT/MYp+LDXgmFTLQNYbDTzrEzqNuO2ZPn9Kpg+xpbm9XtP7ZLw3Ep2BCmSqtnll/OdxAqLb4DTN4/wWdrjnFC+L/oQEECu646"
	parentRememberMeID := "parent_remember_me_id0123456789"

	client := Client{
		Key: key,
		httpClient: &mockHTTPClient{
			do: func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: 200,
					Body: ioutil.NopCloser(strings.NewReader(`{"receipt":{"wrapped_receipt_key": "` + wrappedReceiptKey +
						`","other_party_profile_content": "` + otherPartyProfileContent +
						`","parent_remember_me_id":"` + parentRememberMeID + `", "sharing_outcome":"SUCCESS"}}`)),
				}, nil
			},
		},
	}

	_, activityDetails, errorStrings := client.getActivityDetails(encryptedToken)

	assert.Assert(t, is.Nil(errorStrings))
	assert.Equal(t, activityDetails.ParentRememberMeID(), parentRememberMeID)
}
func TestYotiClient_ParseWithoutProfile_Success(t *testing.T) {
	key, _ := ioutil.ReadFile("test-key.pem")
	rememberMeID := "remember_me_id0123456789"

	var otherPartyProfileContents = []string{
		`"other_party_profile_content": null,`,
		`"other_party_profile_content": "",`,
		``}

	for _, otherPartyProfileContent := range otherPartyProfileContents {

		client := Client{
			Key: key,
			httpClient: &mockHTTPClient{
				do: func(*http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: 200,
						Body: ioutil.NopCloser(strings.NewReader(`{"receipt":{"wrapped_receipt_key": "` + wrappedReceiptKey + `",` +
							otherPartyProfileContent + `"remember_me_id":"` + rememberMeID + `", "sharing_outcome":"SUCCESS"}}`)),
					}, nil
				},
			},
		}

		userProfile, activityDetails, err := client.getActivityDetails(encryptedToken)

		assert.Assert(t, is.Nil(err))
		assert.Equal(t, userProfile.ID, rememberMeID)
		assert.Equal(t, activityDetails.RememberMeID(), rememberMeID)
	}
}

func TestYotiClient_ParseWithoutRememberMeID_Success(t *testing.T) {
	key, _ := ioutil.ReadFile("test-key.pem")

	var otherPartyProfileContents = []string{
		`"other_party_profile_content": null,`,
		`"other_party_profile_content": "",`}

	for _, otherPartyProfileContent := range otherPartyProfileContents {

		client := Client{
			Key: key,
			httpClient: &mockHTTPClient{
				do: func(*http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: 200,
						Body: ioutil.NopCloser(strings.NewReader(`{"receipt":{"wrapped_receipt_key": "` + wrappedReceiptKey + `",` +
							otherPartyProfileContent + `"sharing_outcome":"SUCCESS"}}`)),
					}, nil
				},
			},
		}

		_, _, err := client.getActivityDetails(encryptedToken)

		assert.Assert(t, is.Nil(err))
	}
}

func TestYotiClient_PerformAmlCheck_Success(t *testing.T) {
	key, _ := ioutil.ReadFile("test-key.pem")

	client := Client{
		Key: key,
		httpClient: &mockHTTPClient{
			do: func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: 200,
					Body:       ioutil.NopCloser(strings.NewReader(`{"on_fraud_list":true,"on_pep_list":true,"on_watch_list":true}`)),
				}, nil
			},
		},
	}

	result, err := client.PerformAmlCheck(createStandardAmlProfile())

	assert.Assert(t, is.Nil(err))

	assert.Check(t, result.OnFraudList)
	assert.Check(t, result.OnPEPList)
	assert.Check(t, result.OnWatchList)

}

func TestYotiClient_PerformAmlCheck_Unsuccessful(t *testing.T) {
	key, _ := ioutil.ReadFile("test-key.pem")
	client := Client{
		Key: key,
		httpClient: &mockHTTPClient{
			do: func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: 503,
					Body:       ioutil.NopCloser(strings.NewReader(`SERVICE UNAVAILABLE - Unable to reach the Integrity Service`)),
				}, nil
			},
		},
	}

	_, err := client.PerformAmlCheck(createStandardAmlProfile())

	var expectedErrString = "AML Check was unsuccessful"

	assert.Assert(t, err != nil)
	assert.Check(t, strings.HasPrefix(err.Error(), expectedErrString))

}

func TestYotiClient_ParseIsAgeVerifiedValue_True(t *testing.T) {
	trueValue := []byte("true")

	isAgeVerified, err := parseIsAgeVerifiedValue(trueValue)

	assert.Assert(t, is.Nil(err), "Failed to parse IsAgeVerified value")
	assert.Check(t, *isAgeVerified)
}

func TestYotiClient_ParseIsAgeVerifiedValue_False(t *testing.T) {
	falseValue := []byte("false")

	isAgeVerified, err := parseIsAgeVerifiedValue(falseValue)

	assert.Assert(t, is.Nil(err), "Failed to parse IsAgeVerified value")
	assert.Check(t, !*isAgeVerified)

}
func TestYotiClient_ParseIsAgeVerifiedValue_InvalidValueThrowsError(t *testing.T) {
	invalidValue := []byte("invalidBool")

	_, err := parseIsAgeVerifiedValue(invalidValue)

	assert.Assert(t, err != nil)
}
func TestYotiClient_UnmarshallJSONValue_InvalidValueThrowsError(t *testing.T) {
	invalidStructuredAddress := []byte("invalidBool")

	_, err := attribute.UnmarshallJSON(invalidStructuredAddress)

	assert.Assert(t, err != nil)
}

func TestYotiClient_UnmarshallJSONValue_ValidValue(t *testing.T) {
	const (
		countryIso  = "IND"
		nestedValue = "NestedValue"
	)

	var structuredAddress = []byte(`[
	{
		"address_format": 2,
		"building": "House No.86-A",		
		"state": "Punjab",
		"postal_code": "141012",
		"country_iso": "` + countryIso + `",
		"country": "India",
		"formatted_address": "House No.86-A\nRajgura Nagar\nLudhina\nPunjab\n141012\nIndia",
		"1":
		{
			"1-1":
			{
			  "1-1-1": "` + nestedValue + `"
			}
		}
	}
	]`)

	parsedStructuredAddress, err := attribute.UnmarshallJSON(structuredAddress)

	assert.Assert(t, is.Nil(err), "Failed to parse structured address")

	parsedStructuredAddressInterfaceSlice := parsedStructuredAddress.([]interface{})

	parsedStructuredAddressMap := parsedStructuredAddressInterfaceSlice[0].(map[string]interface{})
	actualCountryIso := parsedStructuredAddressMap["country_iso"]

	assert.Equal(t, countryIso, actualCountryIso)
}

func TestYotiClient_MissingPostalAddress_UsesFormattedAddress(t *testing.T) {
	var formattedAddressText = `House No.86-A\nRajgura Nagar\nLudhina\nPunjab\n141012\nIndia`

	var structuredAddressBytes = []byte(`
	{
		"address_format": 2,
		"building": "House No.86-A",
		"formatted_address": "` + formattedAddressText + `"
	}
	`)

	structuredAddress, err := attribute.UnmarshallJSON(structuredAddressBytes)

	assert.Assert(t, is.Nil(err), "Failed to parse structured address")

	var userProfile = UserProfile{
		ID:                      "remember_me_id0123456789",
		OtherAttributes:         make(map[string]AttributeValue),
		StructuredPostalAddress: structuredAddress,
		Address:                 ""}

	var jsonAttribute = &yotiprotoattr.Attribute{
		Name:        AttrConstStructuredPostalAddress,
		Value:       structuredAddressBytes,
		ContentType: yotiprotoattr.ContentType_JSON,
		Anchors:     []*yotiprotoattr.Anchor{},
	}

	profile := createProfileWithSingleAttribute(jsonAttribute)

	profileAddress, profileErr := ensureAddressProfile(profile)
	assert.Assert(t, is.Nil(profileErr), "Failed to add formatted address to address on Profile")

	userProfileAddress, userProfileErr := ensureAddressUserProfile(userProfile)
	assert.Assert(t, is.Nil(userProfileErr), "Failed to add formatted address to address on UserProfile")

	escapedFormattedAddressText := strings.Replace(formattedAddressText, `\n`, "\n", -1)

	assert.Equal(t, profileAddress, escapedFormattedAddressText, "Address does not equal the expected formatted address.")
	assert.Equal(t, userProfileAddress, escapedFormattedAddressText, "Address does not equal the expected formatted address.")

	var structuredPostalAddress *attribute.JSONAttribute
	structuredPostalAddress, err = profile.StructuredPostalAddress()

	assert.Assert(t, is.Nil(err))
	assert.Equal(t, structuredPostalAddress.ContentType, yotiprotoattr.ContentType_JSON, "Retrieved attribute does not have the correct type")
}

func TestYotiClient_PresentPostalAddress_DoesntUseFormattedAddress(t *testing.T) {
	var addressText = `PostalAddress`

	var structuredAddressBytes = []byte(`
	{
		"address_format": 2,
		"building": "House No.86-A",
		"formatted_address": "FormattedAddress"
	}`)
	structuredAddress, err := attribute.UnmarshallJSON(structuredAddressBytes)

	assert.Assert(t, is.Nil(err), "Failed to parse structured address")

	var result = UserProfile{
		ID:                      "remember_me_id0123456789",
		OtherAttributes:         make(map[string]AttributeValue),
		StructuredPostalAddress: structuredAddress,
		Address:                 addressText}

	newFormattedAddress, err := ensureAddressUserProfile(result)

	assert.Assert(t, is.Nil(err), "Failure when getting formatted address")
	assert.Equal(t, newFormattedAddress, "", "Address should be unchanged when it is present")
}

func TestYotiClient_MissingFormattedAddress_AddressUnchanged(t *testing.T) {
	var structuredAddressBytes = []byte(`
	{
		"address_format": 2,
		"building": "House No.86-A"
	}`)

	structuredAddress, err := attribute.UnmarshallJSON(structuredAddressBytes)

	assert.Assert(t, is.Nil(err), "Failed to parse structured address")

	var result = UserProfile{
		ID:                      "remember_me_id0123456789",
		OtherAttributes:         make(map[string]AttributeValue),
		StructuredPostalAddress: structuredAddress,
		Address:                 ""}

	address, err := ensureAddressUserProfile(result)

	assert.Assert(t, is.Nil(err), "Failed to add formatted address to address")
	assert.Equal(t, address, "", "Formatted address missing, but address was still changed")
}

func TestProfile_GetAttribute_EmptyString(t *testing.T) {
	emptyString := ""
	attributeValue := []byte(emptyString)

	var attr = &yotiprotoattr.Attribute{
		Name:        attributeName,
		Value:       attributeValue,
		ContentType: yotiprotoattr.ContentType_STRING,
		Anchors:     []*yotiprotoattr.Anchor{},
	}

	result := createProfileWithSingleAttribute(attr)
	att := result.GetAttribute(attributeName)

	assert.Equal(t, att.Name, attributeName)
	assert.Equal(t, att.Value().(string), emptyString)
}

func TestProfile_GetApplicationAttribute(t *testing.T) {
	var attr = &yotiprotoattr.Attribute{
		Name:        attributeName,
		ContentType: yotiprotoattr.ContentType_STRING,
		Anchors:     []*yotiprotoattr.Anchor{},
	}

	appProfile := createProfileWithSingleAttribute(attr)
	attribute := appProfile.GetAttribute(attributeName)
	assert.Equal(t, attribute.Name, attributeName)
}

func TestProfile_GetApplicationName(t *testing.T) {
	attributeValue := "APPLICATION NAME"
	var attr = &yotiprotoattr.Attribute{
		Name:        "application_name",
		Value:       []byte(attributeValue),
		ContentType: yotiprotoattr.ContentType_STRING,
		Anchors:     []*yotiprotoattr.Anchor{},
	}

	appProfile := createAppProfileWithSingleAttribute(attr)
	assert.Equal(t, attributeValue, appProfile.ApplicationName().Value())
}

func TestProfile_GetApplicationURL(t *testing.T) {
	attributeValue := "APPLICATION URL"
	var attr = &yotiprotoattr.Attribute{
		Name:        "application_url",
		Value:       []byte(attributeValue),
		ContentType: yotiprotoattr.ContentType_STRING,
		Anchors:     []*yotiprotoattr.Anchor{},
	}

	appProfile := createAppProfileWithSingleAttribute(attr)
	assert.Equal(t, attributeValue, appProfile.ApplicationURL().Value())
}

func TestProfile_GetApplicationLogo(t *testing.T) {
	attributeValue := "APPLICATION LOGO"
	var attr = &yotiprotoattr.Attribute{
		Name:        "application_logo",
		Value:       []byte(attributeValue),
		ContentType: yotiprotoattr.ContentType_JPEG,
		Anchors:     []*yotiprotoattr.Anchor{},
	}

	appProfile := createAppProfileWithSingleAttribute(attr)
	assert.Equal(t, 16, len(appProfile.ApplicationLogo().Value().Data))
}

func TestProfile_GetApplicationBGColor(t *testing.T) {
	attributeValue := "BG VALUE"
	var attr = &yotiprotoattr.Attribute{
		Name:        "application_receipt_bgcolor",
		Value:       []byte(attributeValue),
		ContentType: yotiprotoattr.ContentType_STRING,
		Anchors:     []*yotiprotoattr.Anchor{},
	}

	appProfile := createAppProfileWithSingleAttribute(attr)
	assert.Equal(t, attributeValue, appProfile.ApplicationReceiptBgColor().Value())
}

func TestProfile_GetAttribute_Int(t *testing.T) {
	intValues := [5]int{0, 1, 123, -10, -1}

	for _, integer := range intValues {
		assertExpectedIntegerIsReturned(t, integer)
	}
}

func assertExpectedIntegerIsReturned(t *testing.T, intValue int) {
	intAsString := strconv.Itoa(intValue)

	var attr = &yotiprotoattr.Attribute{
		Name:        attributeName,
		Value:       []byte(intAsString),
		ContentType: yotiprotoattr.ContentType_INT,
		Anchors:     []*yotiprotoattr.Anchor{},
	}

	result := createProfileWithSingleAttribute(attr)
	att := result.GetAttribute(attributeName)

	assert.Equal(t, att.Value().(int), intValue)
}

func TestProfile_GetAttribute_InvalidInt_ReturnsNil(t *testing.T) {
	invalidIntValue := "1985-01-01"

	var attr = &yotiprotoattr.Attribute{
		Name:        attributeName,
		Value:       []byte(invalidIntValue),
		ContentType: yotiprotoattr.ContentType_INT,
		Anchors:     []*yotiprotoattr.Anchor{},
	}

	result := createProfileWithSingleAttribute(attr)

	log.SetOutput(ioutil.Discard)
	att := result.GetAttribute(attributeName)

	assert.Assert(t, is.Nil(att))
}

func TestEmptyStringIsAllowed(t *testing.T) {
	attributeValueString := ""
	attributeValue := []byte(attributeValueString)

	var attr = &yotiprotoattr.Attribute{
		Name:        AttrConstGender,
		Value:       attributeValue,
		ContentType: yotiprotoattr.ContentType_STRING,
		Anchors:     []*yotiprotoattr.Anchor{},
	}

	profile := createProfileWithSingleAttribute(attr)
	att := profile.Gender()

	assert.Equal(t, att.Value(), attributeValueString)
}

func TestProfile_GetAttribute_Time(t *testing.T) {
	dateStringValue := "1985-01-01"
	expectedDate := time.Date(1985, time.January, 1, 0, 0, 0, 0, time.UTC)

	attributeValueTime := []byte(dateStringValue)

	var attr = &yotiprotoattr.Attribute{
		Name:        attributeName,
		Value:       attributeValueTime,
		ContentType: yotiprotoattr.ContentType_DATE,
		Anchors:     []*yotiprotoattr.Anchor{},
	}

	result := createProfileWithSingleAttribute(attr)
	att := result.GetAttribute(attributeName)

	assert.Equal(t, expectedDate, att.Value().(*time.Time).UTC())
}

func TestProfile_GetAttribute_Jpeg(t *testing.T) {
	attributeValue := []byte("value")

	var attr = &yotiprotoattr.Attribute{
		Name:        attributeName,
		Value:       attributeValue,
		ContentType: yotiprotoattr.ContentType_JPEG,
		Anchors:     []*yotiprotoattr.Anchor{},
	}

	result := createProfileWithSingleAttribute(attr)
	att := result.GetAttribute(attributeName)

	assert.DeepEqual(t, att.Value().([]byte), attributeValue)
}

func TestProfile_GetAttribute_Png(t *testing.T) {
	attributeValue := []byte("value")

	var attr = &yotiprotoattr.Attribute{
		Name:        attributeName,
		Value:       attributeValue,
		ContentType: yotiprotoattr.ContentType_PNG,
		Anchors:     []*yotiprotoattr.Anchor{},
	}

	result := createProfileWithSingleAttribute(attr)
	att := result.GetAttribute(attributeName)

	assert.DeepEqual(t, att.Value().([]byte), attributeValue)
}

func TestProfile_GetAttribute_Bool(t *testing.T) {
	var initialBoolValue = true
	attributeValue := []byte(strconv.FormatBool(initialBoolValue))

	var attr = &yotiprotoattr.Attribute{
		Name:        attributeName,
		Value:       attributeValue,
		ContentType: yotiprotoattr.ContentType_STRING,
		Anchors:     []*yotiprotoattr.Anchor{},
	}

	result := createProfileWithSingleAttribute(attr)
	att := result.GetAttribute(attributeName)

	boolValue, err := strconv.ParseBool(att.Value().(string))

	assert.Assert(t, is.Nil(err))
	assert.Equal(t, initialBoolValue, boolValue)
}

func TestProfile_GetAttribute_JSON(t *testing.T) {
	addressFormat := "2"

	var structuredAddressBytes = []byte(`
		{
			"address_format": "` + addressFormat + `",
			"building": "House No.86-A"
		}`)

	var attr = &yotiprotoattr.Attribute{
		Name:        attributeName,
		Value:       structuredAddressBytes,
		ContentType: yotiprotoattr.ContentType_JSON,
		Anchors:     []*yotiprotoattr.Anchor{},
	}

	result := createProfileWithSingleAttribute(attr)
	att := result.GetAttribute(attributeName)

	retrievedAttributeMap := att.Value().(map[string]interface{})
	actualAddressFormat := retrievedAttributeMap["address_format"]

	assert.Equal(t, actualAddressFormat, addressFormat)
}

func TestProfile_GetAttribute_Undefined(t *testing.T) {
	attributeValueString := "value"
	attributeValue := []byte(attributeValueString)

	var attr = &yotiprotoattr.Attribute{
		Name:        attributeName,
		Value:       attributeValue,
		ContentType: yotiprotoattr.ContentType_STRING,
		Anchors:     []*yotiprotoattr.Anchor{},
	}

	result := createProfileWithSingleAttribute(attr)
	att := result.GetAttribute(attributeName)

	assert.Equal(t, att.Name, attributeName)
	assert.Equal(t, att.Value().(string), attributeValueString)
}
func TestProfile_GetAttribute_ReturnsNil(t *testing.T) {
	result := Profile{
		baseProfile{
			attributeSlice: []*yotiprotoattr.Attribute{},
		},
	}

	attribute := result.GetAttribute("attributeName")

	assert.Assert(t, is.Nil(attribute))
}

func TestProfile_StringAttribute(t *testing.T) {
	attributeName := AttrConstNationality
	attributeValueString := "value"
	attributeValueBytes := []byte(attributeValueString)

	var as = &yotiprotoattr.Attribute{
		Name:        attributeName,
		Value:       attributeValueBytes,
		ContentType: yotiprotoattr.ContentType_STRING,
		Anchors:     []*yotiprotoattr.Anchor{},
	}

	result := createProfileWithSingleAttribute(as)

	assert.Equal(t, result.Nationality().Value(), attributeValueString)

	assert.Equal(t, result.Nationality().ContentType, yotiprotoattr.ContentType_STRING)
}

func TestProfile_AttributeProperty_RetrievesAttribute(t *testing.T) {
	attributeName := AttrConstSelfie
	attributeValue := []byte("value")

	var attributeImage = &yotiprotoattr.Attribute{
		Name:        attributeName,
		Value:       attributeValue,
		ContentType: yotiprotoattr.ContentType_PNG,
		Anchors:     []*yotiprotoattr.Anchor{},
	}

	result := createProfileWithSingleAttribute(attributeImage)
	selfie := result.Selfie()

	assert.Equal(t, selfie.Name, attributeName)
	assert.DeepEqual(t, attributeValue, selfie.Value().Data)
	assert.Equal(t, selfie.ContentType, yotiprotoattr.ContentType_PNG)
}

func TestAttributeImage_Image_Png(t *testing.T) {
	attributeName := AttrConstSelfie
	byteValue := []byte("value")

	var attributeImage = &yotiprotoattr.Attribute{
		Name:        attributeName,
		Value:       byteValue,
		ContentType: yotiprotoattr.ContentType_PNG,
		Anchors:     []*yotiprotoattr.Anchor{},
	}

	result := createProfileWithSingleAttribute(attributeImage)
	selfie := result.Selfie()

	assert.DeepEqual(t, selfie.Value().Data, byteValue)
}

func TestAttributeImage_Image_Jpeg(t *testing.T) {
	attributeName := AttrConstSelfie
	byteValue := []byte("value")

	var attributeImage = &yotiprotoattr.Attribute{
		Name:        attributeName,
		Value:       byteValue,
		ContentType: yotiprotoattr.ContentType_JPEG,
		Anchors:     []*yotiprotoattr.Anchor{},
	}

	result := createProfileWithSingleAttribute(attributeImage)
	selfie := result.Selfie()

	assert.DeepEqual(t, selfie.Value().Data, byteValue)
}

func TestAttributeImage_Image_Default(t *testing.T) {
	attributeName := AttrConstSelfie
	byteValue := []byte("value")

	var attributeImage = &yotiprotoattr.Attribute{
		Name:        attributeName,
		Value:       byteValue,
		ContentType: yotiprotoattr.ContentType_PNG,
		Anchors:     []*yotiprotoattr.Anchor{},
	}
	result := createProfileWithSingleAttribute(attributeImage)
	selfie := result.Selfie()

	assert.DeepEqual(t, selfie.Value().Data, byteValue)
}
func TestAttributeImage_Base64Selfie_Png(t *testing.T) {
	attributeName := AttrConstSelfie
	imageBytes := []byte("value")

	var attributeImage = &yotiprotoattr.Attribute{
		Name:        attributeName,
		Value:       imageBytes,
		ContentType: yotiprotoattr.ContentType_PNG,
		Anchors:     []*yotiprotoattr.Anchor{},
	}

	result := createProfileWithSingleAttribute(attributeImage)

	base64ImageExpectedValue := base64.StdEncoding.EncodeToString(imageBytes)

	expectedBase64Selfie := "data:image/png;base64;," + base64ImageExpectedValue

	base64Selfie := result.Selfie().Value().Base64URL()

	assert.Equal(t, base64Selfie, expectedBase64Selfie)
}

func TestAttributeImage_Base64URL_Jpeg(t *testing.T) {
	attributeName := AttrConstSelfie
	imageBytes := []byte("value")

	var attributeImage = &yotiprotoattr.Attribute{
		Name:        attributeName,
		Value:       imageBytes,
		ContentType: yotiprotoattr.ContentType_JPEG,
		Anchors:     []*yotiprotoattr.Anchor{},
	}

	result := createProfileWithSingleAttribute(attributeImage)

	base64ImageExpectedValue := base64.StdEncoding.EncodeToString(imageBytes)

	expectedBase64Selfie := "data:image/jpeg;base64;," + base64ImageExpectedValue

	base64Selfie := result.Selfie().Value().Base64URL()

	assert.Equal(t, base64Selfie, expectedBase64Selfie)
}

func TestAnchorParser_Passport(t *testing.T) {
	log.SetOutput(ioutil.Discard)

	anchorSlice := createAnchorSliceFromTestFile(t, "testanchorpassport.txt")

	var structuredAddressBytes = []byte(`
	{
		"address_format": 2,
		"building": "House No.86-A"
	}`)

	a := &yotiprotoattr.Attribute{
		Name:        AttrConstStructuredPostalAddress,
		Value:       structuredAddressBytes,
		ContentType: yotiprotoattr.ContentType_JSON,
		Anchors:     anchorSlice,
	}

	result := createProfileWithSingleAttribute(a)

	var actualStructuredPostalAddress *attribute.JSONAttribute

	actualStructuredPostalAddress, err := result.StructuredPostalAddress()

	assert.Assert(t, is.Nil(err))

	actualAnchor := actualStructuredPostalAddress.Anchors()[0]

	assert.Equal(t, actualAnchor, actualStructuredPostalAddress.Sources()[0], "Anchors and Sources should be the same when there is only one Source")
	assert.Equal(t, actualAnchor.Type(), anchor.AnchorTypeSource)

	expectedDate := time.Date(2018, time.April, 12, 13, 14, 32, 835537e3, time.UTC)
	actualDate := actualAnchor.SignedTimestamp().Timestamp().UTC()
	assert.Equal(t, actualDate, expectedDate)

	expectedSubType := "OCR"
	assert.Equal(t, actualAnchor.SubType(), expectedSubType)

	expectedValue := "PASSPORT"
	assert.Equal(t, actualAnchor.Value()[0], expectedValue)

	actualSerialNo := actualAnchor.OriginServerCerts()[0].SerialNumber
	assertServerCertSerialNo(t, "277870515583559162487099305254898397834", actualSerialNo)
}

func TestAnchorParser_DrivingLicense(t *testing.T) {
	anchorSlice := createAnchorSliceFromTestFile(t, "testanchordrivinglicense.txt")

	attribute := &yotiprotoattr.Attribute{
		Name:        AttrConstGender,
		Value:       []byte("value"),
		ContentType: yotiprotoattr.ContentType_STRING,
		Anchors:     anchorSlice,
	}

	result := createProfileWithSingleAttribute(attribute)

	genderAttribute := result.Gender()
	resultAnchor := genderAttribute.Anchors()[0]

	assert.Equal(t, resultAnchor, genderAttribute.Sources()[0], "Anchors and Sources should be the same when there is only one Source")
	assert.Equal(t, resultAnchor.Type(), anchor.AnchorTypeSource)

	expectedDate := time.Date(2018, time.April, 11, 12, 13, 3, 923537e3, time.UTC)
	actualDate := resultAnchor.SignedTimestamp().Timestamp().UTC()
	assert.Equal(t, actualDate, expectedDate)

	expectedSubType := ""
	assert.Equal(t, resultAnchor.SubType(), expectedSubType)

	expectedValue := "DRIVING_LICENCE"
	assert.Equal(t, resultAnchor.Value()[0], expectedValue)

	actualSerialNo := resultAnchor.OriginServerCerts()[0].SerialNumber
	assertServerCertSerialNo(t, "46131813624213904216516051554755262812", actualSerialNo)
}

func TestAnchorParser_UnknownAnchor(t *testing.T) {
	anchorSlice := createAnchorSliceFromTestFile(t, "testanchorunknown.txt")

	attr := &yotiprotoattr.Attribute{
		Name:        AttrConstDateOfBirth,
		Value:       []byte("1999-01-01"),
		ContentType: yotiprotoattr.ContentType_DATE,
		Anchors:     anchorSlice,
	}

	result := createProfileWithSingleAttribute(attr)

	DoB, err := result.DateOfBirth()

	assert.Assert(t, is.Nil(err))
	resultAnchor := DoB.Anchors()[0]

	expectedDate := time.Date(2019, time.March, 5, 10, 45, 11, 840037e3, time.UTC)
	actualDate := resultAnchor.SignedTimestamp().Timestamp().UTC()
	assert.Equal(t, actualDate, expectedDate)

	expectedSubType := "TEST UNKNOWN SUB TYPE"
	expectedType := anchor.AnchorTypeUnknown
	assert.Equal(t, resultAnchor.SubType(), expectedSubType)
	assert.Equal(t, resultAnchor.Type(), expectedType)
	assert.Equal(t, len(resultAnchor.Value()), 0)
}

func TestAnchorParser_YotiAdmin(t *testing.T) {
	anchorSlice := createAnchorSliceFromTestFile(t, "testanchoryotiadmin.txt")

	attr := &yotiprotoattr.Attribute{
		Name:        AttrConstDateOfBirth,
		Value:       []byte("1999-01-01"),
		ContentType: yotiprotoattr.ContentType_DATE,
		Anchors:     anchorSlice,
	}

	result := createProfileWithSingleAttribute(attr)

	DoB, err := result.DateOfBirth()

	assert.Assert(t, is.Nil(err))

	resultAnchor := DoB.Anchors()[0]

	assert.Equal(t, resultAnchor, DoB.Verifiers()[0])

	assert.Equal(t, resultAnchor.Type(), anchor.AnchorTypeVerifier)

	expectedDate := time.Date(2018, time.April, 11, 12, 13, 4, 95238e3, time.UTC)
	actualDate := resultAnchor.SignedTimestamp().Timestamp().UTC()
	assert.Equal(t, actualDate, expectedDate)

	expectedSubType := ""
	assert.Equal(t, resultAnchor.SubType(), expectedSubType)

	expectedValue := "YOTI_ADMIN"
	assert.Equal(t, resultAnchor.Value()[0], expectedValue)

	actualSerialNo := resultAnchor.OriginServerCerts()[0].SerialNumber
	assertServerCertSerialNo(t, "256616937783084706710155170893983549581", actualSerialNo)
}

func TestAnchors_None(t *testing.T) {
	anchorSlice := []*anchor.Anchor{}

	sources := anchor.GetSources(anchorSlice)
	assert.Equal(t, len(sources), 0, "GetSources should not return anything with empty anchors")

	verifiers := anchor.GetVerifiers(anchorSlice)
	assert.Equal(t, len(verifiers), 0, "GetVerifiers should not return anything with empty anchors")
}

func TestDateOfBirthAttribute(t *testing.T) {
	protoAttribute := createAttributeFromTestFile(t, "testattributedateofbirth.txt")

	dateOfBirthAttribute, err := attribute.NewTime(protoAttribute)

	assert.Assert(t, is.Nil(err))

	expectedDateOfBirth := time.Date(1970, time.December, 01, 0, 0, 0, 0, time.UTC)
	actualDateOfBirth := dateOfBirthAttribute.Value()

	assert.Assert(t, actualDateOfBirth.Equal(expectedDateOfBirth))
}

func TestNewImageSlice(t *testing.T) {
	protoAttribute := createAttributeFromTestFile(t, "testattributemultivalue.txt")

	documentImagesAttribute, err := attribute.NewImageSlice(protoAttribute)

	assert.Assert(t, is.Nil(err))

	assertIsExpectedDocumentImagesAttribute(t, documentImagesAttribute.Value(), documentImagesAttribute.Anchors()[0])
}

func TestImageSliceNotCreatedWithNonMultiValueType(t *testing.T) {
	attributeValueString := "value"
	attributeValue := []byte(attributeValueString)

	var attr = &yotiprotoattr.Attribute{
		Name:        attributeName,
		Value:       attributeValue,
		ContentType: yotiprotoattr.ContentType_STRING,
		Anchors:     []*yotiprotoattr.Anchor{},
	}

	_, err := attribute.NewImageSlice(attr)

	assert.Assert(t, err != nil, "Expected error when creating image slice from attribute which isn't of multi-value type")
}

func TestMultiValueNotCreatedWithNonMultiValueType(t *testing.T) {
	attributeValueString := "value"
	attributeValue := []byte(attributeValueString)

	var attr = &yotiprotoattr.Attribute{
		Name:        attributeName,
		Value:       attributeValue,
		ContentType: yotiprotoattr.ContentType_STRING,
		Anchors:     []*yotiprotoattr.Anchor{},
	}

	_, err := attribute.NewMultiValue(attr)

	assert.Assert(t, err != nil, "Expected error when creating multi value from attribute which isn't of multi-value type")
}

func TestNewMultiValue(t *testing.T) {
	protoAttribute := createAttributeFromTestFile(t, "testattributemultivalue.txt")

	multiValueAttribute, err := attribute.NewMultiValue(protoAttribute)

	assert.Assert(t, is.Nil(err))

	var documentImagesAttributeItems []*attribute.Image = attribute.CreateImageSlice(multiValueAttribute.Value())

	assertIsExpectedDocumentImagesAttribute(t, documentImagesAttributeItems, multiValueAttribute.Anchors()[0])
}

func TestProfileAllowsMutipleAttributesWithSameName(t *testing.T) {
	firstAttribute := createStringAttribute("full_name", []byte("some_value"), []*yotiprotoattr.Anchor{})
	secondAttribute := createStringAttribute("full_name", []byte("some_other_value"), []*yotiprotoattr.Anchor{})

	var attributeSlice []*yotiprotoattr.Attribute
	attributeSlice = append(attributeSlice, firstAttribute, secondAttribute)

	var profile = Profile{
		baseProfile{
			attributeSlice: attributeSlice,
		},
	}

	var fullNames []*attribute.GenericAttribute = profile.GetAttributes("full_name")

	assert.Assert(t, is.Equal(len(fullNames), 2))
	assert.Assert(t, is.Equal(fullNames[0].Value().(string), "some_value"))
	assert.Assert(t, is.Equal(fullNames[1].Value().(string), "some_other_value"))
}

func TestInvalidMultiValueNotReturned(t *testing.T) {
	var invalidMultiValueItem = &yotiprotoattr.MultiValue_Value{
		ContentType: yotiprotoattr.ContentType_DATE,
		Data:        []byte("invalid"),
	}

	var stringMultiValueItem = &yotiprotoattr.MultiValue_Value{
		ContentType: yotiprotoattr.ContentType_STRING,
		Data:        []byte("string"),
	}

	var multiValueItemSlice = []*yotiprotoattr.MultiValue_Value{invalidMultiValueItem, stringMultiValueItem}

	var multiValueStruct = &yotiprotoattr.MultiValue{
		Values: multiValueItemSlice,
	}

	var marshalledMultiValueData = marshallMultiValue(t, multiValueStruct)
	attributeName := "nestedMultiValue"

	var protoAttribute = &yotiprotoattr.Attribute{
		Name:        attributeName,
		Value:       marshalledMultiValueData,
		ContentType: yotiprotoattr.ContentType_MULTI_VALUE,
		Anchors:     []*yotiprotoattr.Anchor{},
	}

	profile := createProfileWithSingleAttribute(protoAttribute)

	assert.Assert(t, is.Nil(profile.GetAttribute(attributeName)))
}

func TestNestedMultiValue(t *testing.T) {
	var innerMultiValueProtoValue []byte = createAttributeFromTestFile(t, "testattributemultivalue.txt").Value

	var stringMultiValueItem = &yotiprotoattr.MultiValue_Value{
		ContentType: yotiprotoattr.ContentType_STRING,
		Data:        []byte("string"),
	}

	var multiValueItem = &yotiprotoattr.MultiValue_Value{
		ContentType: yotiprotoattr.ContentType_MULTI_VALUE,
		Data:        innerMultiValueProtoValue,
	}

	var multiValueItemSlice = []*yotiprotoattr.MultiValue_Value{stringMultiValueItem, multiValueItem}

	multiValueAttribute, err := createMultiValueAttribute(t, multiValueItemSlice)

	assert.Assert(t, is.Nil(err))

	for key, value := range multiValueAttribute.Value() {
		switch key {
		case 0:
			value0 := value.GetValue()

			assert.Equal(t, value0.(string), "string")
		case 1:
			value1 := value.GetValue()

			innerItems, ok := value1.([]*attribute.Item)
			assert.Assert(t, ok)

			for innerKey, item := range innerItems {
				switch innerKey {
				case 0:
					assertIsExpectedImage(t, parseImage(t, item.GetValue()), "jpeg", "vWgD//2Q==")

				case 1:
					assertIsExpectedImage(t, parseImage(t, item.GetValue()), "jpeg", "38TVEH/9k=")
				}
			}
		}
	}
}

func TestMultiValueGenericGetter(t *testing.T) {
	protoAttribute := createAttributeFromTestFile(t, "testattributemultivalue.txt")
	profile := createProfileWithSingleAttribute(protoAttribute)

	multiValueAttribute := profile.GetAttribute(AttrConstDocumentImages)

	// We need to cast, since GetAttribute always returns generic attributes
	multiValueAttributeValue := multiValueAttribute.Value().([]*attribute.Item)
	imageSlice := attribute.CreateImageSlice(multiValueAttributeValue)

	assertIsExpectedDocumentImagesAttribute(t, imageSlice, multiValueAttribute.Anchors()[0])
}

func parseImage(t *testing.T, innerImageInterface interface{}) *attribute.Image {
	innerImageBytes, ok := innerImageInterface.([]byte)
	assert.Assert(t, ok)

	innerImage, err := attribute.ParseImageValue(yotiprotoattr.ContentType_JPEG, innerImageBytes)
	assert.Assert(t, is.Nil(err))

	return innerImage
}

func assertIsExpectedDocumentImagesAttribute(t *testing.T, actualDocumentImages []*attribute.Image, anchor *anchor.Anchor) {

	assert.Equal(t, len(actualDocumentImages), 2, "This Document Images attribute should have two images")

	assertIsExpectedImage(t, actualDocumentImages[0], "jpeg", "vWgD//2Q==")
	assertIsExpectedImage(t, actualDocumentImages[1], "jpeg", "38TVEH/9k=")

	expectedValue := "NATIONAL_ID"
	assert.Equal(t, anchor.Value()[0], expectedValue)

	expectedSubType := "STATE_ID"
	assert.Equal(t, anchor.SubType(), expectedSubType)
}

func assertIsExpectedImage(t *testing.T, image *attribute.Image, imageType string, expectedBase64URLLast10 string) {
	assert.Equal(t, image.Type, imageType)

	actualBase64URL := image.Base64URL()

	ActualBase64URLLast10Chars := actualBase64URL[len(actualBase64URL)-10:]

	assert.Equal(t, ActualBase64URLLast10Chars, expectedBase64URLLast10)
}

func marshallMultiValue(t *testing.T, multiValue *yotiprotoattr.MultiValue) []byte {
	marshalled, err := proto.Marshal(multiValue)

	assert.Assert(t, is.Nil(err))

	return marshalled
}

func assertServerCertSerialNo(t *testing.T, expectedSerialNo string, actualSerialNo *big.Int) {
	expectedSerialNoBigInt := new(big.Int)
	expectedSerialNoBigInt, ok := expectedSerialNoBigInt.SetString(expectedSerialNo, 10)
	assert.Assert(t, ok, "Unexpected error when setting string as big int")

	assert.Equal(t, expectedSerialNoBigInt.Cmp(actualSerialNo), 0) //0 == equivalent
}

func createMultiValueAttribute(t *testing.T, multiValueItemSlice []*yotiprotoattr.MultiValue_Value) (*attribute.MultiValueAttribute, error) {
	var multiValueStruct = &yotiprotoattr.MultiValue{
		Values: multiValueItemSlice,
	}

	var marshalledMultiValueData = marshallMultiValue(t, multiValueStruct)
	attributeName := "nestedMultiValue"

	var protoAttribute = &yotiprotoattr.Attribute{
		Name:        attributeName,
		Value:       marshalledMultiValueData,
		ContentType: yotiprotoattr.ContentType_MULTI_VALUE,
		Anchors:     []*yotiprotoattr.Anchor{},
	}

	return attribute.NewMultiValue(protoAttribute)
}

func createAttributeFromTestFile(t *testing.T, filename string) *yotiprotoattr.Attribute {
	attributeBytes := decodeTestFile(t, filename)

	attributeStruct := &yotiprotoattr.Attribute{}

	err2 := proto.Unmarshal(attributeBytes, attributeStruct)

	assert.Assert(t, is.Nil(err2))

	return attributeStruct
}

func createStringAttribute(name string, value []byte, anchors []*yotiprotoattr.Anchor) *yotiprotoattr.Attribute {
	return &yotiprotoattr.Attribute{
		Name:        name,
		Value:       value,
		ContentType: yotiprotoattr.ContentType_STRING,
		Anchors:     anchors,
	}
}

func createAnchorSliceFromTestFile(t *testing.T, filename string) []*yotiprotoattr.Anchor {
	anchorBytes := decodeTestFile(t, filename)

	protoAnchor := &yotiprotoattr.Anchor{}
	err2 := proto.Unmarshal(anchorBytes, protoAnchor)
	assert.Assert(t, is.Nil(err2))

	protoAnchors := append([]*yotiprotoattr.Anchor{}, protoAnchor)

	return protoAnchors
}

func decodeTestFile(t *testing.T, filename string) (result []byte) {
	base64Bytes := readTestFile(t, filename)
	base64String := string(base64Bytes)
	filebytes, err := base64.StdEncoding.DecodeString(base64String)

	assert.Assert(t, is.Nil(err))

	return filebytes
}

func createProfileWithSingleAttribute(attr *yotiprotoattr.Attribute) Profile {
	var attributeSlice []*yotiprotoattr.Attribute
	attributeSlice = append(attributeSlice, attr)

	return Profile{
		baseProfile{
			attributeSlice: attributeSlice,
		},
	}
}

func createAppProfileWithSingleAttribute(attr *yotiprotoattr.Attribute) ApplicationProfile {
	var attributeSlice []*yotiprotoattr.Attribute
	attributeSlice = append(attributeSlice, attr)

	return ApplicationProfile{
		baseProfile{
			attributeSlice: attributeSlice,
		},
	}
}

func readTestFile(t *testing.T, filename string) (result []byte) {
	b, err := ioutil.ReadFile(filename)
	assert.Assert(t, is.Nil(err))

	return b
}

func createStandardAmlProfile() (result AmlProfile) {
	var amlAddress = AmlAddress{
		Country: "GBR"}

	var amlProfile = AmlProfile{
		GivenNames: "Edward Richard George",
		FamilyName: "Heath",
		Address:    amlAddress}

	return amlProfile
}
