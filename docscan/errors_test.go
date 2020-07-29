package docscan

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
)

func TestError_ShouldReturnFormattedError(t *testing.T) {
	jsonBytes, _ := json.Marshal(ErrorDO{
		Code:    "SOME_CODE",
		Message: "some message",
		Error: []ErrorItemDO{
			ErrorItemDO{
				Message:  "some property message",
				Property: "some.property",
			},
		},
	})

	err := NewError(
		errors.New("some error"),
		&http.Response{
			StatusCode: 401,
			Body:       ioutil.NopCloser(bytes.NewReader(jsonBytes)),
		},
	)

	assert.ErrorContains(t, err, "SOME_CODE - some message: some.property: `some property message`")
}

func TestError_ShouldReturnFormattedErrorCodeAndMessageOnly(t *testing.T) {
	jsonBytes, _ := json.Marshal(ErrorDO{
		Code:    "SOME_CODE",
		Message: "some message",
	})

	err := NewError(
		errors.New("some error"),
		&http.Response{
			StatusCode: 400,
			Body:       ioutil.NopCloser(bytes.NewReader(jsonBytes)),
		},
	)

	assert.ErrorContains(t, err, "400: SOME_CODE - some message")
}

func TestError_ShouldReturnFormattedError_ReturnWrappedErrorByDefault(t *testing.T) {
	err := NewError(
		errors.New("some error"),
		&http.Response{
			StatusCode: 401,
		},
	)

	assert.ErrorContains(t, err, "some error")
}

func TestError_ShouldReturnFormattedError_ShouldUnwrapOriginalError(t *testing.T) {
	wrappedError := errors.New("some error")
	err := NewError(
		wrappedError,
		&http.Response{
			StatusCode: 401,
		},
	)

	assert.ErrorContains(t, err, "some error")
	assert.Equal(t, err.Unwrap(), wrappedError)
}

func TestError_ShouldReturnFormattedError_ReturnWrappedErrorWhenInvalidJSON(t *testing.T) {
	response := &http.Response{
		StatusCode: 400,
		Body:       ioutil.NopCloser(strings.NewReader("some invalid JSON")),
	}
	err := NewError(
		errors.New("some error"),
		response,
	)

	assert.ErrorContains(t, err, "some error")

	errorResponse := err.Response
	assert.Equal(t, response, errorResponse)

	body, _ := ioutil.ReadAll(errorResponse.Body)
	assert.Equal(t, string(body), "some invalid JSON")
}

func TestError_ShouldReturnFormattedError_IgnoreUnknownErrorItems(t *testing.T) {
	jsonString := "{\"message\": \"some message\", \"code\": \"SOME_CODE\", \"error\": [{\"some_key\": \"some value\"}]}"
	response := &http.Response{
		StatusCode: 400,
		Body:       ioutil.NopCloser(strings.NewReader(jsonString)),
	}
	err := NewError(
		errors.New("some error"),
		response,
	)

	assert.ErrorContains(t, err, "400: SOME_CODE - some message")

	errorResponse := err.Response
	assert.Equal(t, response, errorResponse)

	body, _ := ioutil.ReadAll(errorResponse.Body)
	assert.Equal(t, string(body), jsonString)
}