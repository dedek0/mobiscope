package main

import (
	"bytes"
	"testing"

	"github.com/dedek0/mobiscope/internal/models"
	"github.com/dedek0/mobiscope/internal/pipeline"
	"github.com/stretchr/testify/assert"
)

func TestParseStageList(t *testing.T) {
	assert.Nil(t, parseStageList(""))
	assert.Equal(t, []string{"jadx", "gitleaks"}, parseStageList(" jadx, ,gitleaks "))
}

func TestPrintDiff(t *testing.T) {
	var buf bytes.Buffer
	printDiff(&buf, "old.apk", "new.apk", pipeline.DiffResult{
		New: []models.Finding{{
			Severity: models.SeverityHigh,
			Title:    "New issue",
			Location: models.Location{File: "A.java", Line: 7},
		}},
		Resolved:  []models.Finding{{Severity: models.SeverityLow, Title: "Fixed issue"}},
		Unchanged: 3,
	})
	out := buf.String()
	assert.Contains(t, out, "old.apk -> new.apk")
	assert.Contains(t, out, "new 1, resolved 1, unchanged 3")
	assert.Contains(t, out, "[high] New issue (A.java:7)")
	assert.Contains(t, out, "[low] Fixed issue (-)")
}
