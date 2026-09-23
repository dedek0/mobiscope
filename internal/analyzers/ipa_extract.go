package analyzers

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dedek0/mobiscope/internal/models"
)

const (
	ipaName         = "ipa-extract"
	ipaTimeout      = 5 * time.Minute
	maxZipEntries   = 20000
	maxZipEntrySize = 512 << 20
)

// IPAExtract unpacks an IPA (a ZIP archive) into workdir/extract with
// zip-slip protection.
type IPAExtract struct {
	runner CommandRunner
}

func NewIPAExtract() *IPAExtract {
	return &IPAExtract{runner: &DefaultCommandRunner{}}
}

func NewIPAExtractWithRunner(runner CommandRunner) *IPAExtract {
	return &IPAExtract{runner: runner}
}

func (e *IPAExtract) Name() string { return ipaName }

// Available is always satisfied: extraction is done in-process via archive/zip
// so no external binary is required.
func (e *IPAExtract) Available() error { return nil }

func (e *IPAExtract) Run(ctx context.Context, target string, workdir string) (models.ToolResult, error) {
	start := time.Now()
	result := models.ToolResult{
		ToolName:  e.Name(),
		Version:   toolVersion,
		StartedAt: start,
	}

	if err := ctx.Err(); err != nil {
		result.Duration = time.Since(start)
		result.Error = err.Error()
		return result, err
	}

	outDir := IPAExtractArtifactPath(workdir)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, fmt.Errorf("creating extract dir: %w", err)
	}

	rejected, err := safeUnzip(target, outDir)
	result.Duration = time.Since(start)
	if err != nil {
		result.Error = err.Error()
		return result, fmt.Errorf("extracting IPA: %w", err)
	}

	raw, _ := json.Marshal(map[string]interface{}{
		"output_dir": outDir,
		"app_bundle": appBundleDir(workdir),
		"zip_slip":   rejected,
	})
	result.Output = raw
	return result, nil
}

// ipaExtractOutput is the JSON shape written by IPAExtract.Run.
type ipaExtractOutput struct {
	ZipSlip []string `json:"zip_slip"`
}

// ConvertIPAExtractFindings returns zip-slip findings produced during extraction.
func ConvertIPAExtractFindings(raw []byte, sessionID string) []models.Finding {
	var payload ipaExtractOutput
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil
	}
	findings := make([]models.Finding, 0, len(payload.ZipSlip))
	for _, entry := range payload.ZipSlip {
		f := iosFinding(ipaName, models.CategoryManifestIssue, entry, entry,
			"Zip-slip entry in IPA",
			fmt.Sprintf("Archive entry %q escapes the extraction directory.", entry),
			models.SeverityHigh, models.SensitivityInternal, 1.0)
		findings = append(findings, withSession(f, sessionID))
	}
	return findings
}

// safeUnzip extracts src into dst, refusing entries that escape dst.
// Returns the list of rejected entries.
func safeUnzip(src, dst string) ([]string, error) {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	if len(zr.File) > maxZipEntries {
		return nil, fmt.Errorf("too many entries in archive: %d > %d", len(zr.File), maxZipEntries)
	}

	dstAbs, err := filepath.Abs(dst)
	if err != nil {
		return nil, err
	}

	var rejected []string
	for _, f := range zr.File {
		name := filepath.FromSlash(f.Name)
		clean := filepath.Clean(name)
		if clean == "." || clean == "" {
			continue
		}
		// Reject absolute paths and any .. traversal.
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
			rejected = append(rejected, f.Name)
			continue
		}

		dest := filepath.Join(dstAbs, clean)
		if !strings.HasPrefix(dest, dstAbs+string(os.PathSeparator)) {
			rejected = append(rejected, f.Name)
			continue
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(dest, 0o755); err != nil {
				return rejected, err
			}
			continue
		}

		if f.UncompressedSize64 > maxZipEntrySize {
			rejected = append(rejected, f.Name)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return rejected, err
		}

		rc, err := f.Open()
		if err != nil {
			return rejected, err
		}

		if f.Mode()&os.ModeSymlink != 0 {
			// Never materialize symlinks from an untrusted archive.
			rejected = append(rejected, f.Name)
			rc.Close()
			continue
		}

		outFile, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode().Perm()|0o600)
		if err != nil {
			rc.Close()
			return rejected, err
		}

		_, copyErr := io.Copy(outFile, io.LimitReader(rc, maxZipEntrySize))
		rc.Close()
		closeErr := outFile.Close()
		if copyErr != nil {
			return rejected, copyErr
		}
		if closeErr != nil {
			return rejected, closeErr
		}
	}
	return rejected, nil
}
