package sandbox

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/getyoti/yoti-go-sdk/v3/consts"
)

// TokenRequest describes a sandbox token request
type TokenRequest struct {
	RememberMeID string      `json:"remember_me_id"`
	Attributes   []Attribute `json:"profile_attributes"`
}

// WithRememberMeID adds the Remember Me ID to the returned ActivityDetails.
// The value returned in ActivityDetails will be the Base64 encoded value of the string specified here.
func (t TokenRequest) WithRememberMeID(rememberMeId string) TokenRequest {
	t.RememberMeID = rememberMeId
	return t
}

// WithAttribute adds a new attribute to the sandbox token request
func (t TokenRequest) WithAttribute(name, value string, anchors []Anchor) TokenRequest {
	if anchors == nil {
		anchors = make([]Anchor, 0)
	}
	attribute := Attribute{
		Name:    name,
		Value:   value,
		Anchors: anchors,
	}

	return t.WithAttributeStruct(attribute)
}

// WithAttributeStruct adds a new attribute struct to the sandbox token request
func (t TokenRequest) WithAttributeStruct(attribute Attribute) TokenRequest {
	t.Attributes = append(t.Attributes, attribute)
	return t
}

// WithGivenNames adds given names to the sandbox token request
func (t TokenRequest) WithGivenNames(value string, anchors []Anchor) TokenRequest {
	return t.WithAttribute(consts.AttrGivenNames, value, anchors)
}

// WithFamilyName adds a family name to the sandbox token request
func (t TokenRequest) WithFamilyName(value string, anchors []Anchor) TokenRequest {
	return t.WithAttribute(consts.AttrFamilyName, value, anchors)
}

// WithFullName adds a full name to the sandbox token request
func (t TokenRequest) WithFullName(value string, anchors []Anchor) TokenRequest {
	return t.WithAttribute(consts.AttrFullName, value, anchors)
}

// WithDateOfBirth adds a date of birth to the sandbox token request
func (t TokenRequest) WithDateOfBirth(value time.Time, anchors []Anchor) TokenRequest {
	formattedTime := value.Format("2006-01-02")
	return t.WithAttribute(consts.AttrDateOfBirth, formattedTime, anchors)
}

// WithAgeVerification adds an age-based derivation attribute to the sandbox token request
func (t TokenRequest) WithAgeVerification(dateOfBirth time.Time, derivation Derivation, anchors []Anchor) TokenRequest {
	if anchors == nil {
		anchors = []Anchor{}
	}
	attribute := Attribute{
		Name:       consts.AttrDateOfBirth,
		Value:      dateOfBirth.Format("2006-01-02"),
		Derivation: derivation.ToString(),
		Anchors:    anchors,
	}
	t.Attributes = append(t.Attributes, attribute)
	return t
}

// WithGender adds a gender to the sandbox token request
func (t TokenRequest) WithGender(value string, anchors []Anchor) TokenRequest {
	return t.WithAttribute(consts.AttrGender, value, anchors)
}

// WithPhoneNumber adds a phone number to the sandbox token request
func (t TokenRequest) WithPhoneNumber(value string, anchors []Anchor) TokenRequest {
	return t.WithAttribute(consts.AttrMobileNumber, value, anchors)
}

// WithNationality adds a nationality to the sandbox token request
func (t TokenRequest) WithNationality(value string, anchors []Anchor) TokenRequest {
	return t.WithAttribute(consts.AttrNationality, value, anchors)
}

// WithPostalAddress adds a formatted address to the sandbox token request
func (t TokenRequest) WithPostalAddress(value string, anchors []Anchor) TokenRequest {
	return t.WithAttribute(consts.AttrAddress, value, anchors)
}

// WithStructuredPostalAddress adds a JSON address to the sandbox token request
func (t TokenRequest) WithStructuredPostalAddress(value map[string]interface{}, anchors []Anchor) TokenRequest {
	data, _ := json.Marshal(value)
	return t.WithAttribute(consts.AttrStructuredPostalAddress, string(data), anchors)
}

// WithSelfie adds a selfie image to the sandbox token request
func (t TokenRequest) WithSelfie(value []byte, anchors []Anchor) TokenRequest {
	return t.WithBase64Selfie(base64.StdEncoding.EncodeToString(value), anchors)
}

// WithBase64Selfie adds a base 64 selfie image to the sandbox token request
func (t TokenRequest) WithBase64Selfie(base64Value string, anchors []Anchor) TokenRequest {
	return t.WithAttribute(
		consts.AttrSelfie,
		base64Value,
		anchors,
	)
}

// WithEmailAddress adds an email address to the sandbox token request
func (t TokenRequest) WithEmailAddress(value string, anchors []Anchor) TokenRequest {
	return t.WithAttribute(consts.AttrEmailAddress, value, anchors)
}

// WithDocumentDetails adds a document details string to the sandbox token request
func (t TokenRequest) WithDocumentDetails(value string, anchors []Anchor) TokenRequest {
	return t.WithAttribute(consts.AttrDocumentDetails, value, anchors)
}

// WithDocumentImages adds document images to the sandbox token request
func (t TokenRequest) WithDocumentImages(value DocumentImages, anchors []Anchor) TokenRequest {
	return t.WithAttribute(consts.AttrDocumentImages, value.getValue(), anchors)
}
