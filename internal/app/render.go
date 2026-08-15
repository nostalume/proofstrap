package app

import (
	"fmt"
	"strings"
)

func RenderPlan(plan Plan) (string, error) {
	canonical, err := DecodePlan(plan.bytes)
	if err != nil || canonical.digest != plan.digest {
		return "", fmt.Errorf("valid sealed plan is required")
	}
	var envelope planEnvelope
	if err := strictJSON(canonical.bytes, &envelope); err != nil {
		return "", err
	}
	status := "applicable"
	if len(envelope.Plan.Blockers) > 0 {
		status = "blocked"
	} else {
		for _, item := range envelope.Plan.Operations {
			if item.Kind == "barrier" {
				status = "progressable"
				break
			}
		}
	}
	var output strings.Builder
	fmt.Fprintf(&output, "status: %s\ndigest: %s\ncheckpoints: %d\n", status, canonical.digest, canonical.Checkpoints())
	for _, item := range envelope.Plan.Blockers {
		fmt.Fprintf(&output, "blocker: %s %s — %s\n", item.Kind, item.Resource, item.Detail)
	}
	for _, item := range envelope.Plan.Operations {
		fmt.Fprintf(&output, "operation: %s", item.ID)
		if len(item.Dependencies) > 0 {
			fmt.Fprintf(&output, " <- %s", strings.Join(item.Dependencies, ", "))
		}
		fmt.Fprintf(&output, " [%s]", item.Kind)
		if item.Kind == "barrier" {
			review, err := decodeBarrierReview(item.Review)
			if err != nil {
				return "", err
			}
			fmt.Fprintf(&output, " — %s", review.Reason)
		}
		fmt.Fprintln(&output)
	}
	return output.String(), nil
}
