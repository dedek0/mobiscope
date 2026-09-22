package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/dedek0/mobiscope/internal/models"
)

// Reporter renders an analysis session to a specific output format.
type Reporter interface {
	Render(session *models.AnalysisSession, w io.Writer) error
}

// JSONReporter writes findings as indented JSON.
type JSONReporter struct{}

func (r *JSONReporter) Render(session *models.AnalysisSession, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(session)
}

// FindingsJSON writes only the findings array as JSON.
type FindingsJSON struct{}

func (r *FindingsJSON) Render(session *models.AnalysisSession, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(session.Findings); err != nil {
		return fmt.Errorf("encoding findings: %w", err)
	}
	return nil
}
