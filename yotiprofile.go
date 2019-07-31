package yoti

import (
	"github.com/getyoti/yoti-go-sdk/v2/attribute"
	"github.com/getyoti/yoti-go-sdk/v2/yotiprotoattr"
)

const (
	attrConstSelfie                    = "selfie"
	attrConstGivenNames                = "given_names"
	attrConstFamilyName                = "family_name"
	attrConstFullName                  = "full_name"
	attrConstMobileNumber              = "phone_number"
	attrConstEmailAddress              = "email_address"
	attrConstDateOfBirth               = "date_of_birth"
	attrConstAddress                   = "postal_address"
	attrConstStructuredPostalAddress   = "structured_postal_address"
	attrConstGender                    = "gender"
	attrConstNationality               = "nationality"
	attrConstDocumentImages            = "document_images"
	attrConstApplicationName           = "application_name"
	attrConstApplicationURL            = "application_url"
	attrConstApplicationLogo           = "application_logo"
	attrConstApplicationReceiptBGColor = "application_receipt_bgcolor"
)

type baseProfile struct {
	attributeSlice []*yotiprotoattr.Attribute
}

// Profile represents the details retrieved for a particular user. Consists of
// Yoti attributes: a small piece of information about a Yoti user such as a
// photo of the user or the user's date of birth.
type Profile struct {
	baseProfile
}

// ApplicationProfile is the profile of an application with convenience methods
// to access well-known attributes.
type ApplicationProfile struct {
	baseProfile
}

// Selfie is a photograph of the user. Will be nil if not provided by Yoti.
func (p Profile) Selfie() *attribute.ImageAttribute {
	return p.GetImageAttribute(attrConstSelfie)
}

// GivenNames corresponds to secondary names in passport, and first/middle names in English. Will be nil if not provided by Yoti.
func (p Profile) GivenNames() *attribute.StringAttribute {
	return p.GetStringAttribute(attrConstGivenNames)
}

// FamilyName corresponds to primary name in passport, and surname in English. Will be nil if not provided by Yoti.
func (p Profile) FamilyName() *attribute.StringAttribute {
	return p.GetStringAttribute(attrConstFamilyName)
}

// FullName represents the user's full name.
// If family_name/given_names are present, the value will be equal to the string 'given_names + " " family_name'.
// Will be nil if not provided by Yoti.
func (p Profile) FullName() *attribute.StringAttribute {
	return p.GetStringAttribute(attrConstFullName)
}

// MobileNumber represents the user's mobile phone number, as verified at registration time.
// The value will be a number in E.164 format (i.e. '+' for international prefix and no spaces, e.g. "+447777123456").
// Will be nil if not provided by Yoti.
func (p Profile) MobileNumber() *attribute.StringAttribute {
	return p.GetStringAttribute(attrConstMobileNumber)
}

// EmailAddress represents the user's verified email address. Will be nil if not provided by Yoti.
func (p Profile) EmailAddress() *attribute.StringAttribute {
	return p.GetStringAttribute(attrConstEmailAddress)
}

// DateOfBirth represents the user's date of birth. Will be nil if not provided by Yoti.
// Has an err value which will be filled if there is an error parsing the date.
func (p Profile) DateOfBirth() (*attribute.TimeAttribute, error) {
	for _, a := range p.attributeSlice {
		if a.Name == attrConstDateOfBirth {
			return attribute.NewTime(a)
		}
	}
	return nil, nil
}

// Address represents the user's address. Will be nil if not provided by Yoti.
func (p Profile) Address() *attribute.StringAttribute {
	return p.GetStringAttribute(attrConstAddress)
}

// StructuredPostalAddress represents the user's address in a JSON format.
// Will be nil if not provided by Yoti. This can be accessed as a
// map[string]string{} using a type assertion, e.g.:
// structuredPostalAddress := structuredPostalAddressAttribute.Value().(map[string]string{})
func (p Profile) StructuredPostalAddress() (*attribute.JSONAttribute, error) {
	return p.GetJSONAttribute(attrConstStructuredPostalAddress)
}

// Gender corresponds to the gender in the registered document; the value will be one of the strings "MALE", "FEMALE", "TRANSGENDER" or "OTHER".
// Will be nil if not provided by Yoti.
func (p Profile) Gender() *attribute.StringAttribute {
	return p.GetStringAttribute(attrConstGender)
}

// Nationality corresponds to the nationality in the passport.
// The value is an ISO-3166-1 alpha-3 code with ICAO9303 (passport) extensions.
// Will be nil if not provided by Yoti.
func (p Profile) Nationality() *attribute.StringAttribute {
	return p.GetStringAttribute(attrConstNationality)
}

// DocumentImages returns a slice of document images cropped from the image in the capture page.
// There can be multiple images as per the number of regions in the capture in this attribute.
// Will be nil if not provided by Yoti.
func (p Profile) DocumentImages() (*attribute.ImageSliceAttribute, error) {
	for _, a := range p.attributeSlice {
		if a.Name == attrConstDocumentImages {
			return attribute.NewImageSlice(a)
		}
	}
	return nil, nil
}

// ApplicationName is the name of the application
func (p ApplicationProfile) ApplicationName() *attribute.StringAttribute {
	return p.GetStringAttribute(attrConstApplicationName)
}

// ApplicationURL is the URL where the application is available at
func (p ApplicationProfile) ApplicationURL() *attribute.StringAttribute {
	return p.GetStringAttribute(attrConstApplicationURL)
}

// ApplicationReceiptBgColor is the background colour that will be displayed on
// each receipt the user gets as a result of a sharing with the application.
func (p ApplicationProfile) ApplicationReceiptBgColor() *attribute.StringAttribute {
	return p.GetStringAttribute(attrConstApplicationReceiptBGColor)
}

// ApplicationLogo is the logo of the application that will be displayed to
// those users that perform a sharing with it.
func (p ApplicationProfile) ApplicationLogo() *attribute.ImageAttribute {
	return p.GetImageAttribute(attrConstApplicationLogo)
}

// GetAttribute retrieve an attribute by name on the Yoti profile. Will return nil if attribute is not present.
func (p baseProfile) GetAttribute(attributeName string) *attribute.GenericAttribute {
	for _, a := range p.attributeSlice {
		if a.Name == attributeName {
			return attribute.NewGeneric(a)
		}
	}
	return nil
}

func (p baseProfile) GetStringAttribute(attributeName string) *attribute.StringAttribute {
	for _, a := range p.attributeSlice {
		if a.Name == attributeName {
			return attribute.NewString(a)
		}
	}
	return nil
}

func (p baseProfile) GetImageAttribute(attributeName string) *attribute.ImageAttribute {
	for _, a := range p.attributeSlice {
		if a.Name == attributeName {
			attribute, err := attribute.NewImage(a)

			if err == nil {
				return attribute
			}
		}
	}
	return nil
}

func (p baseProfile) GetJSONAttribute(attributeName string) (*attribute.JSONAttribute, error) {
	for _, a := range p.attributeSlice {
		if a.Name == attributeName {
			return attribute.NewJSON(a)
		}
	}
	return nil, nil
}
