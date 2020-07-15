package check

import (
	"encoding/json"
	"fmt"

	"github.com/getyoti/yoti-go-sdk/v3/docscan/sandbox/check/report"
	"github.com/getyoti/yoti-go-sdk/v3/docscan/sandbox/filter"
)

func Example_documentFaceMatchCheckBuilder() {
	breakdown, err := report.NewBreakdownBuilder().Build()
	if err != nil {
		return
	}

	recommendation, err := report.NewRecommendationBuilder().Build()
	if err != nil {
		return
	}

	filter, err := filter.NewDocumentFilterBuilder().Build()
	if err != nil {
		return
	}

	check, err := NewDocumentFaceMatchCheckBuilder().
		WithBreakdown(breakdown).
		WithRecommendation(recommendation).
		WithDocumentFilter(filter).
		Build()
	if err != nil {
		return
	}

	data, _ := json.Marshal(check)
	fmt.Println(string(data))
	// Output: {"result":{"report":{"recommendation":{"value":"","reason":"","recovery_suggestion":""},"breakdown":[{"sub_check":"","result":"","details":null}]}},"document_filter":{"document_types":null,"country_codes":null}}
}