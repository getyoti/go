package yoti

import (
	"github.com/getyoti/yoti-go-sdk/v2/attribute"
	"github.com/getyoti/yoti-go-sdk/v2/yotiprotoattr"
)

type baseProfile struct {
	attributeSlice []*yotiprotoattr.Attribute
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

// GetAttributes retrieve a list of attributes by name on the Yoti profile.  Will return an empty list of attribute is not present.
func (p baseProfile) GetAttributes(attributeName string) []*attribute.GenericAttribute {
	var attributes []*attribute.GenericAttribute
	for _, a := range p.attributeSlice {
		if a.Name == attributeName {
			attributes = append(attributes, attribute.NewGeneric(a))
		}
	}
	return attributes
}

// GetStringAttribute retrieves a string attribute by name. Will return nil if attribute is not present.
func (p baseProfile) GetStringAttribute(attributeName string) *attribute.StringAttribute {
	for _, a := range p.attributeSlice {
		if a.Name == attributeName {
			return attribute.NewString(a)
		}
	}
	return nil
}

// GetImageAttribute retrieves an image attribute by name. Will return nil if attribute is not present.
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

// GetJSONAttribute retrieves a JSON attribute by name. Will return nil if attribute is not present.
func (p baseProfile) GetJSONAttribute(attributeName string) (*attribute.JSONAttribute, error) {
	for _, a := range p.attributeSlice {
		if a.Name == attributeName {
			return attribute.NewJSON(a)
		}
	}
	return nil, nil
}
