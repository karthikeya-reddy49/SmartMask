"""Supported application permissions. Roles do not imply grants."""
PERMISSIONS = frozenset({
    "data:read", "data:read_raw", "scan:run", "scan:read", "scan:review",
    "policy:read", "policy:write", "audit:read", "users:manage", "database:select",
})
