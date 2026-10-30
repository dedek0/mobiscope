package analyzers

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDEXDC_Run(t *testing.T) {
	binDir := t.TempDir()
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then echo 'dex-decompile 0.1.0'; exit 0; fi
prev=""
for a in "$@"; do
  if [ "$prev" = "-d" ]; then mkdir -p "$a"; echo 'class Main {}' > "$a/Main.java"; fi
  prev="$a"
done
exit 0
`
	require.NoError(t, os.WriteFile(filepath.Join(binDir, dexdcBinary), []byte(script), 0o755))
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	ResetVersionCache()

	a := NewDEXDC(DEXDCConfig{Deobf: true, Excludes: []string{"android."}})
	workdir := t.TempDir()
	res, err := a.Run(context.Background(), "app.apk", workdir)
	require.NoError(t, err)
	assert.Equal(t, dexdcName, res.ToolName)
	assert.Equal(t, "dex-decompile 0.1.0", res.Version)
	assert.FileExists(t, filepath.Join(workdir, dexdcName, "Main.java"))
	assert.Contains(t, string(res.Output), "stdout")
}

func TestDEXDC_PhaseAndName(t *testing.T) {
	a := NewDEXDC(DEXDCConfig{})
	assert.Equal(t, dexdcName, a.Name())
	assert.Equal(t, PhaseDecompiler, a.Phase())
	assert.Equal(t, filepath.Join("out", dexdcName), DEXDCArtifactPath("out"))
}
