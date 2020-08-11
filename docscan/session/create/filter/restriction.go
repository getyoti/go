package filter

// TypeRestriction is a restriction of the type of document required
type TypeRestriction struct {
	Inclusion     inclusionType `json:"inclusion"`
	DocumentTypes []string      `json:"document_types"`
}

// CountryRestriction is a restriction of the country in which a document pertains to
type CountryRestriction struct {
	Inclusion    inclusionType `json:"inclusion"`
	CountryCodes []string      `json:"country_codes"`
}
