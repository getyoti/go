package media

import (
	"encoding/base64"
	"fmt"
	"testing"

	"gotest.tools/v3/assert"
)

func TestMedia_Base64Selfie_Png(t *testing.T) {
	imageBase64Value, media := createMedia("png")
	expectedDataUrl := "data:image/png;base64," + imageBase64Value

	assert.Equal(t, expectedDataUrl, media.Base64URL())
}

func TestMedia_Base64Selfie_Jpeg(t *testing.T) {
	imageBase64Value, media := createMedia("jpeg")
	expectedDataUrl := "data:image/jpeg;base64," + imageBase64Value

	assert.Equal(t, expectedDataUrl, media.Base64URL())
}

func createMedia(contentType string) (string, *Value) {
	imageBytes := []byte("value")
	imageBase64Value := base64.StdEncoding.EncodeToString(imageBytes)
	mimeType := fmt.Sprintf("image/%s", contentType)

	media := &Value{
		MimeType: mimeType,
		Data:     imageBytes,
	}
	return imageBase64Value, media
}