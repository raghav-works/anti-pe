# Event Schema

Final scanner output will be JSON.

The event schema will describe the scanned file, PE validation status, model score, applied policy thresholds, verdict, and scanner metadata.

Required top-level fields:

```json
{
  "event_type": "ml_pe_scan",
  "event_version": "1.0",
  "timestamp": "2026-07-08T00:00:00Z",
  "scan_status": "success",
  "file": {},
  "model": {},
  "decision": {},
  "error": null
}
```

`scan_status` values include:

- `success`
- `policy_disabled`
- `skipped_not_pe`
- `skipped_too_large`
- `file_not_found`
- `read_error`
- `parse_error`
- `feature_error`
- `model_error`

`file` includes path, name, size, SHA-256 when readable, PE status, and type such as `windows_pe` or `non_pe`.

`model` includes model name, version, type, feature dimension, and score. A successful PE scan should return a numeric score between 0 and 1.

`decision` includes verdict, action, score, thresholds, and policy mode. Verdicts are `allow`, `log`, `alert`, or `block`. Actions are advisory for scanner v1; direct quarantine/delete/block is not performed by the scanner.

`error` is `null` on success. On skipped or failed scans it contains a code and message.
