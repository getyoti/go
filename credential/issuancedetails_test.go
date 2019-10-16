package credential

import (
	"strings"
	"testing"

	"github.com/getyoti/yoti-go-sdk/v2/test"
	"github.com/getyoti/yoti-go-sdk/v2/yotiprotoshare"
	"github.com/golang/protobuf/proto"

	"gotest.tools/assert"

	is "gotest.tools/assert/cmp"
)

func TestShouldParseThirdPartyAttributeCorrectly(t *testing.T) {
	var thirdPartyAttributeBytes []byte = test.GetTestFileBytes(t, "testcredentialissuancedetails.txt")
	issuanceDetails, err := ParseIssuanceDetails(thirdPartyAttributeBytes)

	assert.Assert(t, is.Nil(err))
	assert.Equal(t, issuanceDetails.IssuingAttributes()[0], "com.thirdparty.id")
	assert.Equal(t, issuanceDetails.Token(), "someIssuanceToken")
	assert.Equal(t,
		issuanceDetails.ExpiryDate().Format("2006-01-02T15:04:05.000Z"),
		"2019-10-15T22:04:05.123Z")
}

func TestCredentialIssuanceDetailsShouldReturnNullIfErrorInParsing(t *testing.T) {
	thirdPartyAttribute := &yotiprotoshare.ThirdPartyAttribute{
		IssuingAttributes: &yotiprotoshare.IssuingAttributes{
			ExpiryDate: "2006-13-02T15:04:05.000Z",
		},
	}

	marshalled, err := proto.Marshal(thirdPartyAttribute)

	assert.Assert(t, is.Nil(err))

	result, err := ParseIssuanceDetails(marshalled)

	assert.Assert(t, is.Nil(result))
	assert.Equal(t, "parsing time \"2006-13-02T15:04:05.000Z\": month out of range", err.Error())
}

func TestInvalidProtobufThrowsError(t *testing.T) {
	result, err := ParseIssuanceDetails([]byte("invalid"))

	assert.Assert(t, is.Nil(result))

	assert.Check(t, strings.HasPrefix(err.Error(), "Unable to parse ThirdPartyAttribute value"))
}
