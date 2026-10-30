# ADR-004: Content-first platform detection

## Status

Accepted

## Context

APK and IPA are both ZIP archives (`PK\x03\x04`), so magic bytes alone cannot
discriminate them. Before `internal/platform` existed, `analyze` treated every
input as an APK: an IPA fed to the CLI ran apktool/jadx and produced an empty,
"clean" report. The platform-detection design intent was recorded before
implementation: inspect the ZIP central directory (no full extract), use the
filename extension only as a tiebreaker, and reject unknown platforms with a
clear error before any tool runs.

## Decision

`platform.Detect(path)` opens the archive with `archive/zip` (central
directory only, nothing decompressed) and classifies by entry names:

1. `Payload/<App>.app/Info.plist` (case-insensitive match, backslashes
   normalized) -> iOS, `FormatIPA`. This check wins if the archive also
   contains Android markers.
2. `AndroidManifest.xml` at the root or in a subdirectory, or any entry with
   prefix `classes` and suffix `.dex` -> Android, `FormatAPK`.
3. No content signal -> tiebreak on the file extension (`.ipa`, `.apk`,
   lowercased).
4. Neither content nor extension matches -> hard error:
   `unrecognized target %q: no AndroidManifest.xml, classes*.dex or
   Payload/*.app/Info.plist`.

Guards around the decision:

- At most `maxEntries = 4096` central-directory entries are inspected so a
  hostile archive with millions of entries cannot stall detection.
- `platform.MustExist` runs first and rejects missing paths and directories.
- `DetectReader` mirrors `Detect` for already-open files (tests).
- `cmd/mobiscope/analyze.go` calls `Detect` before `buildAnalyzers`, so an
  unrecognized file never reaches a tool; the returned `Target{Path, Format,
  Platform}` is the single dispatch point for the Android/iOS stage sets.

## Consequences

### Positive

- Content decides: renaming `sample.zip` to `sample.apk` does not fool it.
- Detection is O(entries) with a hard cap and zero decompression cost.
- Fail-fast with an actionable message instead of an empty report (the bug
  that motivated the ADR).
- One return type feeds both stage selection and `Options.Platform`, so every
  downstream consumer (inventory, reports, SARIF) agrees on the platform.

### Negative

- Archives whose identifying entries sit beyond the first 4096 entries fall
  through to the extension tiebreaker and may be rejected.
- The tiebreaker still trusts the filename for signal-less ZIPs; an empty
  archive named `foo.apk` is accepted as Android and then fails in apktool.
- Entry matching is string-based, not semantic: a file merely *named*
  `AndroidManifest.xml` or `classes.dex` anywhere in the tree marks the
  archive Android; its content is never validated at detection time.
- `PlatformUnknown` is a hard error, so generic ZIPs are unsupported by
  design (they must be renamed to a real platform or repackaged).

## References

- internal/platform/platform.go (Detect, DetectReader, MustExist, maxEntries)
- internal/platform/platform_test.go
- cmd/mobiscope/analyze.go (Detect call, `buildAnalyzers` dispatch)
- internal/models/platform.go (Platform enum: android/ios/unknown)
- [docs/roadmap.md](../roadmap.md) (current plan)
