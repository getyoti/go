package yotierror

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
)

func TestError_ShouldReturnFormattedError(t *testing.T) {
	jsonBytes, _ := json.Marshal(DataObject{
		Code:    "SOME_CODE",
		Message: "some message",
		Errors: []ItemDataObject{
			{
				Message:  "some property message",
				Property: "some.property",
			},
		},
	})

	err := New(
		&http.Response{
			StatusCode: 401,
			Body:       ioutil.NopCloser(bytes.NewReader(jsonBytes)),
		},
	)

	assert.ErrorContains(t, err, "SOME_CODE - some message: some.property: `some property message`")
}

func TestError_ShouldReturnFormattedErrorCodeAndMessageOnly(t *testing.T) {
	jsonBytes, _ := json.Marshal(DataObject{
		Code:    "SOME_CODE",
		Message: "some message",
	})

	err := New(
		&http.Response{
			StatusCode: 400,
			Body:       ioutil.NopCloser(bytes.NewReader(jsonBytes)),
		},
	)

	assert.ErrorContains(t, err, "400: SOME_CODE - some message")
}

func TestError_ShouldReturnFormattedError_ReturnWrappedErrorByDefault(t *testing.T) {
	err := New(
		&http.Response{
			StatusCode: 401,
		},
	)

	assert.ErrorContains(t, err, "401: unknown HTTP error")
}

func TestError_ShouldReturnFormattedError_ReturnWrappedErrorWhenInvalidJSON(t *testing.T) {
	response := &http.Response{
		StatusCode: 400,
		Body:       ioutil.NopCloser(strings.NewReader("some invalid JSON")),
	}
	err := New(
		response,
	)

	assert.ErrorContains(t, err, "400: unknown HTTP error - some invalid JSON")

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
	err := New(
		response,
	)

	assert.ErrorContains(t, err, "400: SOME_CODE - some message")

	errorResponse := err.Response
	assert.Equal(t, response, errorResponse)

	body, _ := ioutil.ReadAll(errorResponse.Body)
	assert.Equal(t, string(body), jsonString)
}

func TestError_ShouldReturnCustomErrorForCode(t *testing.T) {
	response := &http.Response{
		StatusCode: 404,
		Body:       ioutil.NopCloser(strings.NewReader("some body")),
	}
	err := New(
		response,
		map[int]string{404: "some message"},
	)

	assert.ErrorContains(t, err, "404: some message - some body")
}

func TestError_ShouldReturnCustomDefaultError(t *testing.T) {
	response := &http.Response{
		StatusCode: 500,
		Body:       ioutil.NopCloser(strings.NewReader("some body")),
	}
	err := New(
		response,
		map[int]string{-1: "some default message"},
	)

	assert.ErrorContains(t, err, "500: some default message - some body")
}

func TestError_ShouldReturnTemporaryForServerError(t *testing.T) {
	response := &http.Response{
		StatusCode: 500,
	}
	err := New(
		response,
	)

	assert.Check(t, err.Temporary())
}

func TestError_ShouldNotReturnTemporaryForClientError(t *testing.T) {
	response := &http.Response{
		StatusCode: 400,
	}
	err := New(
		response,
	)

	assert.Check(t, !err.Temporary())
}
