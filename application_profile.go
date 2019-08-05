package yoti

import (
	"github.com/getyoti/yoti-go-sdk/v2/attribute"
)

// ApplicationProfile is the profile of an application with convenience methods
// to access well-known attributes.
type ApplicationProfile struct {
	baseProfile
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
