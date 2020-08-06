package media

import (
	"encoding/base64"
	"fmt"
	"testing"

	"gotest.tools/v3/assert"
)

func TestMedia_Base64URL_Png(t *testing.T) {
	imageBase64Value, media := createMedia("png")
	expectedDataUrl := "data:image/png;base64," + imageBase64Value

	assert.Equal(t, expectedDataUrl, media.Base64URL())
}

func TestMedia_Base64URL_Jpeg(t *testing.T) {
	imageBase64Value, media := createMedia("jpeg")
	expectedDataUrl := "data:image/jpeg;base64," + imageBase64Value

	assert.Equal(t, expectedDataUrl, media.Base64URL())
}

func createMedia(contentType string) (string, *Value) {
	imageBytes := []byte("value")
	imageBase64Value := base64.StdEncoding.EncodeToString(imageBytes)
	MIMEType := fmt.Sprintf("image/%s", contentType)

	media := &Value{
		MIMEType: MIMEType,
		Data:     imageBytes,
	}
	return imageBase64Value, media
}
