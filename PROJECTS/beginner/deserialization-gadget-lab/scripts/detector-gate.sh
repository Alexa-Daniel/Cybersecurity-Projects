#!/usr/bin/env bash
# ©AngelaMos | 2026
# detector-gate.sh

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VULNERABLE_IMAGE="ruby:4.0.2-slim"

echo "boundary detector gate"
echo

output="$(docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=1m \
    --user nobody \
    -v "${HERE}/lib:/app/lib:ro" -w /app "${VULNERABLE_IMAGE}" ruby -Ilib -e '
require "rube"
D = Rube::Marshal::BoundaryDetector
CANARY = "/tmp/rube-canary"

hostile = Rube::Chains::ErbDefMethod.canary(CANARY, "fired").serialize
benign  = Marshal.dump({ "user" => "guest", "roles" => [1, 2, 3] })
sinky   = Marshal.dump(Gem::Requirement.new(">= 0"))

strict_hostile = D.new.inspect_stream(hostile)
strict_benign  = D.new.inspect_stream(benign)
strict_sinky   = D.new.inspect_stream(sinky)
allowlisted    = D.new(allowed_class_names: %w[Gem::Requirement Gem::Version]).inspect_stream(sinky)
loose_hostile  = D.new(policy: D::POLICY_DENY_SINKS_ONLY).inspect_stream(hostile)

puts "strict_rejects_cve=#{strict_hostile.rejected?}"
puts "strict_accepts_benign=#{strict_benign.accepted?}"
puts "strict_rejects_sink=#{strict_sinky.rejected?}"
puts "allowlist_does_not_exempt_sink=#{allowlisted.rejected?}"
puts "deny_sinks_only_accepts_cve=#{loose_hostile.accepted?}"

fired = false
if loose_hostile.accepted?
  begin
    Marshal.load(loose_hostile.snapshot).def_method(Module.new, "x")
  rescue StandardError
    nil
  end
  fired = File.exist?(CANARY)
end
puts "documented_bypass_executes=#{fired}"
' 2>&1)"

echo "${output}" | sed 's/^/  /'
echo

failures=0
expect() {
    if echo "${output}" | grep -q "^$1=true$"; then
        echo "  PASS   $2"
    else
        echo "  FAIL   $2"
        failures=$((failures + 1))
    fi
}

expect strict_rejects_cve "strict policy rejects the CVE-2026-41316 payload"
expect strict_accepts_benign "strict policy still accepts a benign primitive stream"
expect strict_rejects_sink "strict policy rejects a sink-bearing stream"
expect allowlist_does_not_exempt_sink "allowlisting a class does not exempt its sink"
expect deny_sinks_only_accepts_cve "deny-sinks-only accepts the CVE payload as documented"
expect documented_bypass_executes "the documented bypass actually executes, so the notice is honest"

echo
if [[ ${failures} -eq 0 ]]; then
    echo "GATE PASSED"
    exit 0
fi

echo "GATE FAILED (${failures})"
exit 1
