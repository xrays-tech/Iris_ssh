#!/usr/bin/env bash
# case_openstack_cross_project_requires_password.sh — appendix C validation:
# scope="cross_project" is the one mode that must use auth_method="password"
# (an application credential cannot span projects). A config that enables
# cross_project with any other auth method is refused at startup — fail loud,
# never a silent fallback.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"

mkdir -p "$IT_WORK_DIR"
KEY="$IT_WORK_DIR/os-hostkey"
[ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N "" -f "$KEY" 2>/dev/null
cat > "$IT_WORK_DIR/bad_cross_appcred.toml" <<EOF
[listen]
addr = "127.0.0.1:2299"
[host_keys]
keys = [ { path = "$KEY", state = "active" } ]
[openstack]
enabled = true
routing = "openstack_only"
authorization = "openstack_only"
allow_any_authenticated_key = true
scope = "cross_project"
auth_method = "application_credential"
application_credential_id = "x"
application_credential_secret = "y"
project_id = "proj-1"
region = "RegionOne"
interface = "public"
nova_endpoint = "http://127.0.0.1:8774/v2.1"
default_backend_user = "alex"
EOF
rc=0
"$GW_BIN" --config "$IT_WORK_DIR/bad_cross_appcred.toml" >/dev/null 2>&1 && rc=1 || rc=0
if [ "$rc" -eq 0 ]; then
  pass "cross_project without password auth is rejected at startup"
else
  fail "cross_project accepted a non-password auth method"
fi
echo "OK: case_openstack_cross_project_requires_password"
