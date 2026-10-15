#!/usr/bin/env bash
# case_openstack_password_not_in_single_project.sh — appendix C validation: a
# password credential is only meaningful (and therefore only allowed) under
# scope="cross_project". The default single_project world keeps its
# application-credential / static-token semantics; configuring password there
# is refused at startup.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"   # defines SUBTOPO_GW_BIN with the repo fallback

KEY="$IT_WORK_DIR/os-hostkey2"
mkdir -p "$IT_WORK_DIR"
[ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N "" -f "$KEY" 2>/dev/null
cat > "$IT_WORK_DIR/bad_password_single.toml" <<EOF
[listen]
addr = "127.0.0.1:2299"
[host_keys]
keys = [ { path = "$KEY", state = "active" } ]
[openstack]
enabled = true
routing = "openstack_only"
authorization = "openstack_only"
allow_any_authenticated_key = true
auth_method = "password"
username = "ops-admin"
password = "pw"
application_credential_id = "unused"
application_credential_secret = "unused"
project_id = "proj-1"
region = "RegionOne"
interface = "public"
nova_endpoint = "http://127.0.0.1:8774/v2.1"
default_backend_user = "alex"
EOF
rc=0
"$SUBTOPO_GW_BIN" --config "$IT_WORK_DIR/bad_password_single.toml" >/dev/null 2>&1 && rc=1 || rc=0
if [ "$rc" -eq 0 ]; then
  pass "password auth without cross_project is rejected at startup"
else
  fail "password accepted for the single_project default"
fi
echo "OK: case_openstack_password_not_in_single_project"
