# Changelog

## v2.0 — Structured detection (boolean + time-based)

### Added
- **Two-phase workflow.** Phase 1 detects the injection; Phase 2 extracts.
- **Automatic blind-type detection.** Tries **boolean-based** first (no waiting, much
  faster) and falls back to **time-based** (`pg_sleep`) only when boolean gives no signal.
- **Auto-calibration of the TRUE/FALSE signal** for boolean blind: diffs **status code →
  body length → a unique body token** to pick a reliable discriminator.
- **Automatic context discovery** across `stacked`, `string-and`, `string-or`,
  `numeric-and`, `numeric-or` — no need to guess `--preset` anymore.
- New flags: `--context`, `--force-boolean`, `--force-time`, `--true-match`,
  `--false-match`, `--len-margin`, `--len-jitter`.

### Changed
- Replaced the old `--preset` selection with detected/pinned `--context`.
- Resume checkpoint signature now includes the detected type + context.
- Output reorganised into clear `PHASE 1` / `PHASE 2` sections.

### Notes
- Existing time-based commands keep working; they now simply report the detected
  type and context. The script filename and import name are unchanged.
