package retrieve

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/getyoti/yoti-go-sdk/v3/docscan/constants"
	"gotest.tools/v3/assert"
)

func TestGetSessionResult_UnmarshalJSON(t *testing.T) {
	authenticityCheckResponse := &CheckResponse{
		Type:  constants.IDDocumentAuthenticity,
		State: "DONE",
	}

	testDate := time.Date(2020, 01, 01, 1, 2, 3, 4, time.UTC)
	faceMatchCheckResponse := &CheckResponse{
		Type:    constants.IDDocumentFaceMatch,
		Created: &testDate,
	}

	textDataCheckResponse := &CheckResponse{
		Type:   constants.IDDocumentTextDataCheck,
		Report: &ReportResponse{},
	}

	livenessCheckResponse := &CheckResponse{
		Type:        constants.Liveness,
		LastUpdated: &testDate,
	}

	idDocComparisonCheckResponse := &CheckResponse{
		Type:  constants.IDDocumentComparison,
		State: "PENDING",
	}

	var checks []*CheckResponse
	checks = append(checks, &CheckResponse{Type: "OTHER_TYPE", ID: "id"})
	checks = append(checks, authenticityCheckResponse)
	checks = append(checks, faceMatchCheckResponse)
	checks = append(checks, textDataCheckResponse)
	checks = append(checks, livenessCheckResponse)
	checks = append(checks, idDocComparisonCheckResponse)

	getSessionResult := GetSessionResult{
		Checks: checks,
	}
	marshalled, err := json.Marshal(&getSessionResult)
	assert.NilError(t, err)

	var result GetSessionResult
	err = json.Unmarshal(marshalled, &result)
	assert.NilError(t, err)

	assert.Equal(t, 6, len(result.Checks))

	assert.Equal(t, 1, len(result.AuthenticityChecks()))
	assert.Equal(t, "DONE", result.AuthenticityChecks()[0].State)

	assert.Equal(t, 1, len(result.FaceMatchChecks()))
	assert.Check(t, result.FaceMatchChecks()[0].Created.Equal(testDate))

	assert.Equal(t, 1, len(result.TextDataChecks()))
	assert.DeepEqual(t, &ReportResponse{}, result.TextDataChecks()[0].Report)

	assert.Equal(t, 1, len(result.LivenessChecks()))
	assert.Check(t, result.LivenessChecks()[0].LastUpdated.Equal(testDate))

	assert.Equal(t, 1, len(result.IDDocumentComparisonChecks()))
	assert.Equal(t, "PENDING", result.IDDocumentComparisonChecks()[0].State)
}

func TestGetSessionResult_UnmarshalJSON_Invalid(t *testing.T) {
	var result GetSessionResult
	err := result.UnmarshalJSON([]byte("some-invalid-json"))
	assert.ErrorContains(t, err, "invalid character")
}
