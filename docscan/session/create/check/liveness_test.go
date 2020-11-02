package check

import (
	"encoding/json"
	"fmt"
	"testing"

	"gotest.tools/v3/assert"
)

func ExampleRequestedLivenessCheckBuilder() {
	check, err := NewRequestedLivenessCheckBuilder().
		ForZoomLiveness().
		WithMaxRetries(9).
		Build()
	if err != nil {
		fmt.Printf("error: %s", err.Error())
		return
	}

	data, err := json.Marshal(check)
	if err != nil {
		fmt.Printf("error: %s", err.Error())
		return
	}

	fmt.Println(string(data))
	// Output: {"type":"LIVENESS","config":{"max_retries":9,"liveness_type":"ZOOM"}}
}

func TestRequestedLivenessCheckBuilder_MaxRetriesIsOmittedIfNotSet(t *testing.T) {
	check, err := NewRequestedLivenessCheckBuilder().
		ForLivenessType("LIVENESS_TYPE").
		Build()

	assert.NilError(t, err)

	result, err := json.Marshal(check)
	assert.NilError(t, err)

	expected := "{\"type\":\"LIVENESS\",\"config\":{\"liveness_type\":\"LIVENESS_TYPE\"}}"

	assert.Equal(t, expected, string(result))
}
