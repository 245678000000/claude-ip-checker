# v1.1.1 GUI QA inventory

- Light 1160x860: reference score not percent; coverage 1/5; unknown signals gray; DNS failure gray; HTTP 403 yellow; mixed RTC mismatch yellow.
- Dark 1160x860: readable cards, source notes, evidence panel, progress and controls.
- Minimum native size 820x640: no horizontal document overflow, stacked cards and usable controls.
- Hide IP toggle: all exit/DNS/RTC/history addresses replaced as text; export redacted regardless of toggle.
- Refresh/change mode: new batch and fresh state; stale callback ignored (Node VM regression).
- Cancel: export status cancelled; UI stops accepting old results.
- View evidence: expands readable redacted JSON.
- Clear history: list empty and reference factors update.
- Update: older release not reported as new.
- Off-happy-path: no host produces no synthetic values; HTTP/DNS errors never show normal.
- Actual macOS: launch built app by explicit path, verify bundled JS loads and real native callbacks; no replace/install, no account operations.
- Save panel/export requires deliberate user action; offline bridge export payload tested separately.
- Windows: cross-compilation only on this Mac; Windows runtime not claimed.
