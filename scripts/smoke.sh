#!/usr/bin/env bash
# Smoke-test mobiscope against a synthetic APK or IPA fixture.
#
# Usage:
#   scripts/smoke.sh apk                 # synthetic Android fixture
#   scripts/smoke.sh ipa                 # synthetic iOS fixture
#   scripts/smoke.sh both
#   scripts/smoke.sh apk real-app.apk    # analyze a real APK
#
# Environment:
#   BINARY    path to the mobiscope binary (default ./bin/mobiscope)
#   WORKDIR   output base directory (default targets/smoke-<platform>)
#   KEEP=1    keep the generated fixtures afterwards
set -euo pipefail

PLATFORM="${1:-both}"
SAMPLE="${2:-}"
KEEP="${KEEP:-0}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="${BINARY:-$ROOT/bin/mobiscope}"
FIXTURES="$ROOT/.smoke-fixtures"

if [ ! -x "$BINARY" ]; then
  echo "==> building $BINARY"
  (cd "$ROOT" && make build)
fi

fail=0
PASS=0
TOTAL=0

check() {
  local label="$1" file="$2" pattern="$3"
  TOTAL=$((TOTAL+1))
  if grep -q "$pattern" "$file" 2>/dev/null; then
    echo "   [ok]   $label"
    PASS=$((PASS+1))
  else
    echo "   [MISS] $label  (pattern: $pattern)"
    fail=1
  fi
}

section() { echo; echo "--- $1"; }

smoke_apk() {
  local fixture="$1"
  local workdir="$ROOT/targets/smoke-apk"
  local stages="inventory"
  if command -v gitleaks >/dev/null 2>&1 && gitleaks version >/dev/null 2>&1; then
    stages="inventory,gitleaks"
  fi
  if command -v semgrep >/dev/null 2>&1 && semgrep --version >/dev/null 2>&1; then
    stages="inventory,gitleaks,semgrep"
  fi

  echo
  echo "============================================================"
  echo "==> [apk] $fixture"
  echo "============================================================"

  rm -rf "$workdir"; mkdir -p "$workdir"

  # Pre-seed the decompiled tree. apktool/jadx need a real APK to decode a
  # binary manifest/DEX; the fixture only has to exercise the inventory,
  # secret patterns and reporting, so we place the sources where the
  # pipeline looks for them: <workdir>/<session>/jadx.
  local session_id
  session_id="$(sha256sum "$fixture" | cut -c1-16)"
  local seed="$workdir/$session_id/jadx"
  section "seeding decompiled tree -> $seed"
  mkdir -p "$seed"
  python3 - "$fixture" "$seed" <<'PYSEED'
import sys, zipfile, os
fx, seed = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(fx) as z:
    for name in z.namelist():
        if name.endswith(".java") or name.endswith(".xml"):
            rel = name.replace("unknown/", "").replace("res/", "res/")
            dest = os.path.join(seed, rel)
            os.makedirs(os.path.dirname(dest) or seed, exist_ok=True)
            with open(dest, "wb") as fh:
                fh.write(z.read(name))
            print("   seeded", dest)
PYSEED

  section "dry-run"
  "$BINARY" analyze "$fixture" --dry-run --workdir "$workdir" 2>&1 | sed 's/^/   /'

  section "analyze (stages: $stages)"
  if ! "$BINARY" analyze "$fixture" --workdir "$workdir" --stages "$stages"; then
    echo "!! analyze failed" >&2
    fail=1
    return
  fi

  local session
  session="$(dirname "$(find "$workdir" -name findings.json | head -1)")"
  if [ -z "$session" ] || [ "$session" = "." ]; then
    echo "!! no session dir with findings.json" >&2; fail=1; return
  fi

  section "artifacts ($session)"
  ls -la "$session" | sed 's/^/   /'

  section "expected signals"
  check "package name"        "$session/findings.json" "com.example.smoke"
  check "debuggable finding"  "$session/findings.json" "debuggable"
  check "dangerous perm"      "$session/findings.json" "CAMERA"
  check "exported provider"   "$session/findings.json" "provider"
  check "cleartext NSC"       "$session/findings.json" "cleartext"
  check "custom trust anchor" "$session/findings.json" "trust"
  check "overridePins"        "$session/findings.json" "overridePins"
  check "AWS key secret"      "$session/findings.json" "AKIA"
  # MD5 detection is a semgrep rule; only required when semgrep ran.
  if echo "$stages" | grep -q semgrep; then
    check "MD5 crypto"        "$session/findings.json" "MD5\|md5"
  else
    echo "   [skip] MD5 crypto (semgrep not available)"
  fi
  check "platform=android"    "$session/session.json"  '"platform": *"android"'
  check "inventory.json"      "$session/inventory.json" "permissions"
  check "report.sarif"        "$session/report.sarif"  "sarif-2.1.0"

  section "findings summary"
  python3 - "$session/findings.json" <<'PY'
import json,sys,collections
d=json.load(open(sys.argv[1]))
print(f"   total: {len(d)}")
for (c,s),n in sorted(collections.Counter((f.get("category"),f.get("severity")) for f in d).items()):
    print(f"   {n:3d}  {c} / {s}")
PY

  section "report preview"
  head -20 "$session/report.md" | sed 's/^/   /'
}

smoke_ipa() {
  local fixture="$1"
  local workdir="$ROOT/targets/smoke-ipa"
  local stages="ipa-extract,plist,macho,codesign,strings,classdump"

  echo
  echo "============================================================"
  echo "==> [ipa] $fixture"
  echo "============================================================"

  rm -rf "$workdir"; mkdir -p "$workdir"

  # Pre-seed the decompiled tree. apktool/jadx need a real APK to decode a
  # binary manifest/DEX; the fixture only has to exercise the inventory,
  # secret patterns and reporting, so we place the sources where the
  # pipeline looks for them: <workdir>/<session>/jadx.
  local session_id
  session_id="$(sha256sum "$fixture" | cut -c1-16)"
  local seed="$workdir/$session_id/jadx"
  section "seeding decompiled tree -> $seed"
  mkdir -p "$seed"
  python3 - "$fixture" "$seed" <<'PYSEED'
import sys, zipfile, os
fx, seed = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(fx) as z:
    for name in z.namelist():
        if name.endswith(".java") or name.endswith(".xml"):
            rel = name.replace("unknown/", "").replace("res/", "res/")
            dest = os.path.join(seed, rel)
            os.makedirs(os.path.dirname(dest) or seed, exist_ok=True)
            with open(dest, "wb") as fh:
                fh.write(z.read(name))
            print("   seeded", dest)
PYSEED

  section "dry-run"
  "$BINARY" analyze "$fixture" --dry-run --workdir "$workdir" 2>&1 | sed 's/^/   /'

  section "analyze (stages: $stages)"
  if ! "$BINARY" analyze "$fixture" --workdir "$workdir" --stages "$stages"; then
    echo "!! analyze failed" >&2
    fail=1
    return
  fi

  local session
  session="$(dirname "$(find "$workdir" -name findings.json | head -1)")"
  if [ -z "$session" ] || [ "$session" = "." ]; then
    echo "!! no session dir with findings.json" >&2; fail=1; return
  fi

  section "artifacts ($session)"
  ls -la "$session" | sed 's/^/   /'

  section "expected signals"
  check "bundle id"            "$session/inventory.json" "com.example.smoke"
  check "bundle id (session)"  "$session/session.json"  "com.example.smoke"
  check "get-task-allow"       "$session/findings.json" "get-task-allow"
  check "ATS arbitrary loads"  "$session/findings.json" "NSAllowsArbitraryLoads\|arbitrary loads"
  check "ATS domain exception" "$session/findings.json" "api.example.com"
  check "file sharing"         "$session/findings.json" "file sharing"
  check "dangerous URL scheme" "$session/findings.json" "https"
  check "encrypted binary"     "$session/findings.json" "Encrypted"
  check "private entitlement"  "$session/findings.json" "com.apple.private"
  check "platform=ios"         "$session/session.json"  '"platform": *"ios"'
  check "min OS recorded"      "$session/inventory.json" "14.0"
  check "dangerous ObjC class" "$session/findings.json" "UIWebView\|NSURLConnection"

  section "findings summary"
  python3 - "$session/findings.json" <<'PY'
import json,sys,collections
d=json.load(open(sys.argv[1]))
print(f"   total: {len(d)}")
for (c,s),n in sorted(collections.Counter((f.get("category"),f.get("severity")) for f in d).items()):
    print(f"   {n:3d}  {c} / {s}")
PY

  section "report preview"
  head -20 "$session/report.md" | sed 's/^/   /'
}

case "$PLATFORM" in
  apk)
    FIXTURE="$SAMPLE"
    if [ -z "$FIXTURE" ]; then
      echo "==> generating Android fixture"
      python3 "$ROOT/scripts/make-fixtures.py" apk -o "$FIXTURES" | sed 's/^/   /'
      FIXTURE="$FIXTURES/smoke.apk"
    fi
    smoke_apk "$FIXTURE"
    ;;
  ipa)
    FIXTURE="$SAMPLE"
    if [ -z "$FIXTURE" ]; then
      echo "==> generating iOS fixture"
      python3 "$ROOT/scripts/make-fixtures.py" ipa -o "$FIXTURES" | sed 's/^/   /'
      FIXTURE="$FIXTURES/smoke.ipa"
    fi
    smoke_ipa "$FIXTURE"
    ;;
  both)
    "$0" apk
    "$0" ipa
    ;;
  *)
    echo "usage: $0 {apk|ipa|both} [real-app.apk|.ipa]" >&2
    exit 2
    ;;
esac

if [ "$KEEP" != "1" ]; then
  rm -rf "$FIXTURES"
fi

echo
echo "============================================================"
if [ "$fail" -ne 0 ]; then
  echo "SMOKE FAILED  ($PASS/$TOTAL checks passed)"
  exit 1
fi
echo "SMOKE PASSED  ($PASS/$TOTAL checks passed)"
