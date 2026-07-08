"""Shared scan status, verdict, and action constants."""

STATUS_SUCCESS = "success"
STATUS_POLICY_DISABLED = "policy_disabled"
STATUS_SKIPPED_NOT_PE = "skipped_not_pe"
STATUS_SKIPPED_TOO_LARGE = "skipped_too_large"
STATUS_FILE_NOT_FOUND = "file_not_found"
STATUS_READ_ERROR = "read_error"
STATUS_PARSE_ERROR = "parse_error"
STATUS_FEATURE_ERROR = "feature_error"
STATUS_MODEL_ERROR = "model_error"

VERDICT_ALLOW = "allow"
VERDICT_LOG = "log"
VERDICT_ALERT = "alert"
VERDICT_BLOCK = "block"

ACTION_ALLOW = "allow"
ACTION_LOG = "log"
ACTION_ALERT = "alert"
ACTION_BLOCK = "block"
ACTION_NONE = "none"

