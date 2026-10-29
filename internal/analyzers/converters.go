package analyzers

import (
	"encoding/json"

	"github.com/dedek0/mobiscope/internal/models"
)

// ConvertFindings lets the pipeline assert a FindingConverter on any analyzer
// instead of growing a switch over analyzer names (PENDING §1.6/§5).
// Each method delegates to the analyzer's package-level converter.

func (a *Gitleaks) ConvertFindings(raw json.RawMessage, sessionID string) []models.Finding {
	return ConvertGitleaksFindings(raw, sessionID)
}

func (a *Semgrep) ConvertFindings(raw json.RawMessage, sessionID string) []models.Finding {
	return ConvertSemgrepFindings(raw, sessionID)
}

func (a *IPAExtract) ConvertFindings(raw json.RawMessage, sessionID string) []models.Finding {
	return ConvertIPAExtractFindings(raw, sessionID)
}

func (a *PlistAnalyzer) ConvertFindings(raw json.RawMessage, sessionID string) []models.Finding {
	return ConvertPlistFindings(raw, sessionID)
}

func (a *MachO) ConvertFindings(raw json.RawMessage, sessionID string) []models.Finding {
	return ConvertMachOFindings(raw, sessionID)
}

func (a *CodeSign) ConvertFindings(raw json.RawMessage, sessionID string) []models.Finding {
	return ConvertCodeSignFindings(raw, sessionID)
}

func (a *Strings) ConvertFindings(raw json.RawMessage, sessionID string) []models.Finding {
	return ConvertStringsFindings(raw, sessionID)
}

func (a *ClassDump) ConvertFindings(raw json.RawMessage, sessionID string) []models.Finding {
	return ConvertClassDumpFindings(raw, sessionID)
}

func (a *ApkSigner) ConvertFindings(raw json.RawMessage, sessionID string) []models.Finding {
	return ConvertApkSignerFindings(raw, sessionID)
}

func (a *ELF) ConvertFindings(raw json.RawMessage, sessionID string) []models.Finding {
	return ConvertELFFindings(raw, sessionID)
}

func (a *AntiAnalysis) ConvertFindings(raw json.RawMessage, sessionID string) []models.Finding {
	return ConvertAntiAnalysisFindings(raw, sessionID)
}
