package check

import (
	"github.com/getyoti/yoti-go-sdk/v3/docscan/sandbox/request/check/report"
)

type check struct {
	Result checkResult `json:"result"`
}

type checkBuilder struct {
	recommendation *report.Recommendation
	breakdowns     []*report.Breakdown
}

type checkResult struct {
	Report checkReport `json:"report"`
}

type checkReport struct {
	Recommendation *report.Recommendation `json:"recommendation,omitempty"`
	Breakdown      []*report.Breakdown    `json:"breakdown,omitempty"`
}

func (b *checkBuilder) withRecommendation(recommendation *report.Recommendation) {
	b.recommendation = recommendation
}

func (b *checkBuilder) withBreakdown(breakdown *report.Breakdown) {
	b.breakdowns = append(b.breakdowns, breakdown)
}

func (b *checkBuilder) build() *check {
	return &check{
		Result: checkResult{
			Report: checkReport{
				Recommendation: b.recommendation,
				Breakdown:      b.breakdowns,
			},
		},
	}
}
