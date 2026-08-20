"""
©AngelaMos | 2026
hash_identifier.py

Identify what kind of hash a string is, by inspecting its shape

When someone hands you a string of gibberish like
`5f4dcc3b5aa765d61d8327deb882cf99` or `$2b$12$EixZaYVK1fsbw1ZfbX3OXe...`,
the first question is: what algorithm produced it? You can NOT crack
or analyze a hash without knowing what flavor of hash you are looking
at. Every cracking tool — hashcat, john the ripper — needs you to
specify an algorithm before it will start

This script does the looking-at part. Given a hash string, it returns
ranked candidates with a confidence score and a short reason

────────────────────────────────────────────────────────────────────
How identification actually works
────────────────────────────────────────────────────────────────────
There is no magic here. Hash strings carry shape clues

  1. PREFIX. Many modern hashes are stored in "PHC string format" —
     a self-describing format that starts with a marker like `$2b$`
     (bcrypt) or `$argon2id$` (Argon2id). When we see a known prefix
     we know the algorithm with HIGH confidence

  2. LENGTH. Raw hex output of a hash function is always the same
     length: MD5 produces 16 bytes = 32 hex chars; SHA-1 produces 20
     bytes = 40 hex chars; SHA-256 produces 32 bytes = 64 hex chars,
     and so on. Length alone narrows the field

  3. CHARSET. Different formats use different alphabets. Hex hashes
     use only 0-9 and a-f. Base64 uses 0-9, A-Z, a-z, +, /, and =.
     A string with `+` in it is not a hex hash

So our algorithm is: try prefix rules first, fall back to length +
charset rules, return the candidates ranked by confidence

────────────────────────────────────────────────────────────────────
What this script can and cannot do
────────────────────────────────────────────────────────────────────
CAN:    suggest likely algorithms for a hash you found
CANNOT: tell you the password the hash was made from
        (that is hashcat's job — see ../../beginner/hash-cracker)

────────────────────────────────────────────────────────────────────
What this file exposes
────────────────────────────────────────────────────────────────────
  HashCandidate          — one ranked guess (algorithm, confidence, reason)
  identify(text)         — return ranked candidates for a hash string
  main()                 — CLI entry point used by `hashid <hash>`
"""

# Standard library: parse command-line flags like `--top 3` into a
# nice object so we do not have to slice `sys.argv` by hand.
import argparse

# Standard library: access to interpreter internals — we use it to
# write to stderr and to exit the process with a specific status code.
import sys

# Standard library: a decorator that turns a class into a small,
# immutable data record without writing `__init__` boilerplate.
from dataclasses import dataclass
from dataclasses import asdict
from functools import cache

# Standard library: a type hint that pins a value to a small fixed
# set of strings (here: "high" / "medium" / "low"). Mypy catches typos.
from typing import Literal

from pathlib import Path

# Third-party (rich): the printer that actually draws the table to
# the terminal, with color and Unicode support.
from rich.console import Console

# Third-party (rich): builds the colored ASCII table we print for
# ranked hash candidates.
from rich.table import Table

# =============================================================================
# Confidence score - floating number between 0 and 1
# =============================================================================
# Score will be determined using different weights based on the match
# and some added score from different smaller hints:
# Scoring:
# prefix match: 0.95
# special shape match: 0.85
# length match (1st candidate): 0.55
# length match (Nth candidate): 0.55 / N
# charset match: small additive bonus
# not-a-hash hint: 0.30

confidence_score: float

CRACK_DIFFICULTY = Literal["trivial", "moderate", "hard", "very_hard"]


# =============================================================================
# Result type — what identify() returns for each guess
# =============================================================================


@dataclass(frozen = True, slots = True)
class HashCandidate:
    """
    One possible identification of a hash string

    `frozen=True` makes the dataclass immutable — once created, its
    fields cannot change. `slots=True` makes instances lightweight in
    memory. Together these two flags create a clean "value object"

    Fields
    ------
    algorithm
        Human-readable algorithm name like "SHA-256" or "bcrypt"
    confidence
        How sure we are. "high" comes from definitive prefix matches,
        "medium" from length matches that have only one obvious
        candidate, "low" for length matches that could be many things
    reason
        Short explanation we display next to the algorithm name. Keeps
        the output debuggable — the user can see WHY each guess fired
    hashcat_mode
        The numerical mode value that hashcat takes for this specific algorithm
    """
    algorithm: str
    confidence: float
    reason: str
    crack_difficulty: CRACK_DIFFICULTY
    hashcat_mode: int | None = None
    
# =============================================================================
# Hashcat modes - maps algorithms to their hashcat mode numerical value
# =============================================================================

HASHCAT_MODES: dict[str, int] = {
    "MD5": 0,
    "SHA1": 100,
    "MySQL323": 200,
    "NTLM": 1000,
    "MD4": 900,
    "RIPEMD-160": 6000,
    "SHA3-224": 17300,
    "SHA-256": 1400,
    "SHA3-256": 17400,
    "BLAKE2s-256": 31000,
    "RIPEMD-320": 33600,
    "SHA3-384": 17500,
    "SHA-512": 1700,
    "SHA3-512": 17600,
    "BLAKE2b-512": 600,
    "Whirlpool": 6100,
    "Argon2id": 34000,
    "Argon2i": 34000,
    "Argon2d": 34000,
    "bcrypt": 3200,
    "SHA-512 crypt": 1800,
    "SHA-256 crypt": 7400,
    "MD5 crypt": 500,
    "Apache MD5-crypt": 1600,
    "yescrypt": 8900,
    "scrypt": 8900,
    "phpass": 400,
    "Drupal 7 (SHA-512)": 7900
}

DIFFICULTY_MAP: dict[str, CRACK_DIFFICULTY] = {
    # ---------------------------------------------------------
    # TRIVIAL (Fast, Unsalted, or Broken)
    # ---------------------------------------------------------
    "MD4": "trivial",
    "MD5": "trivial",
    "SHA1": "trivial",
    "SHA-1": "trivial",
    "NTLM": "trivial",
    "MySQL323": "trivial",
    "CRC-64": "trivial",
    "NetNTLMv1": "trivial",      # Easily downgraded/broken via DES
    "LDAP MD5": "trivial",
    "LDAP SHA": "trivial",
    "RIPEMD-128": "trivial",

    # ---------------------------------------------------------
    # MODERATE (Salted fast hashes, or slower raw algorithms)
    # ---------------------------------------------------------
    "SHA-224": "moderate",
    "SHA-256": "moderate",
    "SHA-384": "moderate",
    "SHA-512": "moderate",
    "SHA3-224": "moderate",
    "SHA3-256": "moderate",
    "SHA3-384": "moderate",
    "SHA3-512": "moderate",
    "BLAKE2s-256": "moderate",
    "BLAKE2b-512": "moderate",
    "RIPEMD-160": "moderate",
    "RIPEMD-256": "moderate",
    "RIPEMD-320": "moderate",
    "Tiger-128": "moderate",
    "Tiger-192": "moderate",
    "Whirlpool": "moderate",
    "MySQL5": "moderate",        # SHA1(SHA1(pass))
    "DES crypt": "moderate",     # Salted, but limited to 8 chars max
    "NetNTLMv2": "moderate",     # HMAC-MD5 based challenge-response
    "LDAP SMD5": "moderate",     # Salted MD5
    "LDAP SSHA": "moderate",     # Salted SHA-1

    # ---------------------------------------------------------
    # HARD (Iterated KDFs - Slows down GPUs significantly)
    # ---------------------------------------------------------
    "MD5 crypt": "hard",         # 1000 iterations of MD5
    "Apache MD5-crypt": "hard",  
    "SHA-256 crypt": "hard",     # 5000 iterations of SHA-256
    "SHA-512 crypt": "hard",     # 5000 iterations of SHA-512
    "phpass": "hard",            # ~8192 iterations of MD5 (WordPress)
    "Drupal 7 (SHA-512)": "hard",
    "Django PBKDF2-SHA1": "hard",
    "Django PBKDF2-SHA256": "hard",
    "macOS / iCloud Keychain": "hard", # Apple PBKDF2-SHA512
    "LDAP CRYPT": "hard",

    # ---------------------------------------------------------
    # VERY HARD (Memory-Hard / ASIC-Resistant / GPU-Resistant)
    # ---------------------------------------------------------
    "bcrypt": "very_hard",
    "scrypt": "very_hard",
    "Argon2id": "very_hard",
    "Argon2i": "very_hard",
    "Argon2d": "very_hard",
    "yescrypt": "very_hard",     # Modern memory-hard Linux default
    "Django bcrypt-SHA256": "very_hard",
    "Django Argon2": "very_hard",
}


# =============================================================================
# Prefix rules — strongest signal we have
# =============================================================================
# Modern hashes use PHC-style strings: a leading `$` marker tells you
# exactly what algorithm produced the hash. When we see one of these
# prefixes we report HIGH confidence. The third element of each tuple
# is a short note we include in the reason field
#
# Order matters when prefixes overlap. We list more specific prefixes
# FIRST so they match before generic ones (e.g. `$argon2id$` before
# `$argon2$` would matter if both existed in the table)

PREFIX_RULES: list[tuple[str, str, str]] = [
    # Argon2 family — won the 2015 Password Hashing Competition
    ("$argon2id$", "Argon2id", "modern PHC string, the current standard"),
    ("$argon2i$", "Argon2i", "PHC string, side-channel-resistant variant"),
    ("$argon2d$", "Argon2d", "PHC string, GPU-resistant variant"),

    # bcrypt and its many variants — workhorse for the past 15 years
    ("$2y$", "bcrypt", "bcrypt PHC string, 2y variant (PHP)"),
    ("$2b$", "bcrypt", "bcrypt PHC string, 2b variant (current)"),
    ("$2a$", "bcrypt", "bcrypt PHC string, 2a variant (legacy)"),
    ("$2x$", "bcrypt", "bcrypt PHC string, 2x variant (legacy fix)"),

    # Unix crypt(3) family — what /etc/shadow uses on Linux
    ("$6$", "SHA-512 crypt", "Unix crypt(3) using SHA-512 (default on Linux)"),
    ("$5$", "SHA-256 crypt", "Unix crypt(3) using SHA-256"),
    ("$1$", "MD5 crypt", "Unix crypt(3) using MD5 (legacy, weak)"),

    # Apache htpasswd MD5 variant — same MD5 family as $1$ above but
    # with Apache's own salt-handling tweak. This is the format that
    # `htpasswd -m` emits by default, which makes it FAR more common
    # in the wild than the Unix $1$ form (every basic-auth tutorial
    # ends with one of these in a .htpasswd file)
    ("$apr1$", "Apache MD5-crypt", "Apache htpasswd MD5 variant (`htpasswd -m`)"),

    # yescrypt — newer Linux default in some distributions
    ("$y$", "yescrypt", "PHC string, modern Linux crypt successor"),

    # phpass — used by WordPress, phpBB, and other PHP apps
    ("$P$", "phpass", "WordPress / phpBB password hash"),
    ("$H$", "phpass", "phpBB-style phpass variant"),

    # Drupal 7
    ("$S$", "Drupal 7 (SHA-512)", "Drupal 7 PHC-style hash"),

    # scrypt as some implementations encode it
    ("$7$", "scrypt", "scrypt PHC-style hash"),

    # Django's default — recognizable by the algorithm name in the prefix
    ("pbkdf2_sha256$", "Django PBKDF2-SHA256", "Django default password hash"),
    ("pbkdf2_sha1$", "Django PBKDF2-SHA1", "Django legacy password hash"),
    ("bcrypt_sha256$", "Django bcrypt-SHA256", "Django bcrypt wrapper"),
    ("argon2$", "Django Argon2", "Django Argon2 wrapper"),

    # macOS / iCloud Keychain
    ("$ml$", "macOS / iCloud Keychain", "macOS / iCloud default password hash, comes from Apple PBKDF2-SHA512"),

    # LDAP password schemes — base64 payload after the marker
    ("{SSHA}", "LDAP SSHA", "LDAP salted SHA-1 (base64 payload)"),
    ("{SHA}", "LDAP SHA", "LDAP SHA-1 (base64 payload)"),
    ("{SMD5}", "LDAP SMD5", "LDAP salted MD5 (base64 payload)"),
    ("{MD5}", "LDAP MD5", "LDAP MD5 (base64 payload)"),
    ("{CRYPT}", "LDAP CRYPT", "LDAP wrapping a crypt(3) hash"),
]


# =============================================================================
# Length-and-hex rules — fallback when no prefix matched
# =============================================================================
# Raw hash output is always the same length, so a string of N hex chars
# narrows down the algorithm. The list of algorithms for each length is
# sorted by REAL-WORLD prevalence. The first item gets MEDIUM confidence
# (the "most likely default"), the rest LOW (still possible)

# Hex chars are 0-9 plus a-f (or A-F if uppercase)
HEX_CHARSET: frozenset[str] = frozenset("0123456789abcdefABCDEF")

# Uppercase-only hex charset — some formats (MySQL5) ONLY ever emit
# uppercase hex because they print via the `%02X` C format specifier,
# so checking membership in this tighter charset lets us reject
# lowercase strings as false-positives instead of confidently saying
# "yes that is MySQL5" to an obviously hand-edited input
_HEX_UPPER_CHARSET: frozenset[str] = frozenset("0123456789ABCDEF")

# Length-in-hex-chars → list of algorithms, ordered by commonality
HEX_LENGTH_RULES: dict[int, list[str]] = {
    # 16 hex chars = 8 bytes = 64 bits. This is the pre-MySQL-4.1
    # OLD_PASSWORD() output — still produced today by MySQL's
    # OLD_PASSWORD() SQL function for legacy compatibility, and
    # still appears in CTFs and old MySQL breach dumps. The only
    # other thing that produces 16 hex chars in a security context
    # is a 64-bit CRC, which is rare enough that MySQL323 outranks it
    16: ["MySQL323", "CRC-64"],
    # 24 hex chars = 12 bytes = 96 bits
    24: ["Tiger-128"],
    # 32 hex chars = 16 bytes = 128 bits
    32: ["MD5", "NTLM", "MD4", "RIPEMD-128"],
    # 40 hex chars = 20 bytes = 160 bits
    40: ["SHA-1", "RIPEMD-160"],
    # 48 hex chars = 24 bytes = 192 bits
    48: ["Tiger-192"],
    # 56 hex chars = 28 bytes = 224 bits
    56: ["SHA-224", "SHA3-224"],
    # 64 hex chars = 32 bytes = 256 bits
    64: ["SHA-256", "SHA3-256", "BLAKE2s-256", "RIPEMD-256"],
    # 80 hex chars = 40 bytes = 320 bits (uncommon)
    80: ["RIPEMD-320"],
    # 96 hex chars = 48 bytes = 384 bits
    96: ["SHA-384", "SHA3-384"],
    # 128 hex chars = 64 bytes = 512 bits
    128: ["SHA-512", "SHA3-512", "BLAKE2b-512", "Whirlpool"],
}

BASE58_CHARS = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
BASE32_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
USERNAME_CHARS = set("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")


# =============================================================================
# Helpers
# =============================================================================


def _is_hex(text: str) -> bool:
    """
    Return True iff every character in text is a hex digit and text is non-empty

    A hash like "5f4dcc..." passes; an empty string or anything with
    a non-hex character fails. We use the HEX_CHARSET frozenset for
    membership tests because `c in frozenset` is O(1) lookup, faster
    than `c in "0123456789abcdef..."` for big inputs
    """
    return bool(text) and all(c in HEX_CHARSET for c in text)


# MySQL5 layout: `*` followed by 40 uppercase hex chars.
# Pulling both numbers out as named constants keeps the helper below
# from reading like sprinkled-in magic numbers — `_MYSQL5_TOTAL_LENGTH`
# tells the reader WHY the helper compares to 41 (40 hex chars + the
# leading `*`) instead of leaving 41 unexplained
_MYSQL5_HEX_BODY_LENGTH = 40
_MYSQL5_TOTAL_LENGTH = _MYSQL5_HEX_BODY_LENGTH + 1


def _is_mysql5(text: str) -> bool:
    """
    Return True for MySQL5 password format: `*` then 40 UPPERCASE hex chars

    MySQL5 stores SHA-1(SHA-1(password)) printed in uppercase hex with
    a leading `*`. Real MySQL5 output uses the `%02X` C format
    specifier, which is uppercase-only. We reject lowercase here so
    we do not return a confident HIGH-confidence "MySQL5" verdict on
    a hand-edited or mistyped string — better to fall through to
    no-match than to lie with conviction

    NOTE: we cannot just call `body.isupper()` to enforce the case.
    Python's `str.isupper` returns False when a string contains NO
    cased characters at all, which would wrongly reject an all-digit
    hex body like "0123456789ABCDEF..." with no letters in it.
    Checking membership in an uppercase-only charset is the test
    that actually matches the spec
    """
    if len(text) != _MYSQL5_TOTAL_LENGTH or not text.startswith("*"):
        return False
    body = text[1 :]
    return all(c in _HEX_UPPER_CHARSET for c in body)


# Traditional DES crypt — legacy /etc/passwd hashes from pre-shadow
# Unix systems. They have no prefix at all: just 13 characters drawn
# from a specific 64-char alphabet (the same alphabet used by all
# crypt(3) variants for their base64-style output). We pull both the
# charset and the expected length out as named constants so the helper
# below reads like its meaning instead of like sprinkled magic numbers
_DESCRYPT_CHARSET: frozenset[str] = frozenset(
    "./0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
)
_DESCRYPT_TOTAL_LENGTH = 13


def _is_descrypt(text: str) -> bool:
    """
    Return True for traditional 13-char DES crypt (legacy /etc/passwd)

    No prefix at all — just 13 characters drawn from `./0-9A-Za-z`.
    Old enough that you mostly see it in retro CTFs now, but real
    enough that hashcat still ships a mode (1500) for cracking it.
    We report MEDIUM (not HIGH) confidence on a match because a 13-char
    string in that charset CAN be other things (some session IDs,
    encoded values), and a beginner deserves an honest confidence
    level rather than a false-positive at HIGH
    """
    return (
        len(text) == _DESCRYPT_TOTAL_LENGTH
        and all(c in _DESCRYPT_CHARSET for c in text)
    )


# =============================================================================
# The actual identifier
# =============================================================================
# pylint flags this function for having many return statements and many
# branches. That is the cost of writing the function as six numbered,
# linear steps — each step gets its own short block and returns the
# moment it finds a match, which is the structure that maps cleanly
# onto the docstring. Refactoring into helper functions would obscure
# the pedagogical line-by-line flow, so we accept the extra returns
# here as a deliberate teaching choice and silence the two warnings
# pylint: disable=too-many-return-statements,too-many-branches

@cache
def identify(raw_input: str) -> list[HashCandidate]:
    """
    Return ranked candidates for what algorithm produced `raw_input`

    Algorithm
    ---------
    Whitespace is trimmed from `raw_input` first. Then the six
    matching steps below run in order — each step's labeled comment
    (`# ----- Step N: ... -----`) inside the function body matches
    the number in this list, so the docstring and the code stay in
    lockstep:

    1. Walk the PREFIX_RULES table. The first prefix that matches
       wins (HIGH confidence). Each table row is unique enough that
       at most one entry can match a given input
    2. Check special non-PHC formats in order — NetNTLMv1/v2
       challenge-response records, MySQL5 (`*<40 hex>`), and the
       legacy 13-char DES crypt. Each has a distinctive shape that
       takes precedence over generic length-based matching
    3. If the input is pure hex, look up its length in
       HEX_LENGTH_RULES and report each candidate. The first entry
       at each length gets MEDIUM confidence (the modern default);
       the rest LOW
    4. If the input has a `$<algo>$...` shape but no PREFIX_RULES
       row matched, fall back to a generic PHC string match — LOW
       confidence because we only matched the shape, not a specific
       rule
    5. If the input looks like a JWT (`eyJ...`) or a base64 blob
       (contains `+`, `/`, or `=`), say so with LOW confidence —
       these are not hashes, but a beginner deserves to know what
       they pasted instead of a silent no-match
    6. If nothing matched at all, return an empty list

    Parameters
    ----------
    raw_input
        The hash string to identify. Whitespace is trimmed before
        analysis but the rest is treated literally — case matters
        because some algorithms use uppercase output

    Returns
    -------
    list[HashCandidate]
        Possibly empty. When non-empty, candidates are ordered by
        confidence (high before medium before low) and within each
        confidence band by likelihood
    """
    # Trim whitespace — copy-pasted hashes often arrive with trailing
    # newlines or leading spaces. We do not modify case because some
    # formats are case-sensitive
    text = raw_input.strip()

    if not text:
        return []
    
    

    # ----- Step 1: prefix rules -----
    # Walk the table top-to-bottom. Entries in PREFIX_RULES are crafted
    # so that no two of them can EVER both match the same input — the
    # first prefix that matches is THE match. So we return it right
    # away instead of continuing the loop. HIGH confidence is the
    # right label because a known prefix is a definitive self-
    # identification: the hash literally announces what algorithm
    # produced it, we are not guessing
    for prefix, algorithm, note in PREFIX_RULES:
        if text.startswith(prefix):
            confidence_score = 0.95
            return [
                HashCandidate(
                    algorithm = algorithm,
                    confidence = confidence_score,
                    reason = f"prefix `{prefix}` — {note}",
                    hashcat_mode = HASHCAT_MODES.get(algorithm),
                    crack_difficulty = DIFFICULTY_MAP[algorithm],
                )
            ]

    # ----- Step 2: special non-PHC formats -----
    # Formats that do not fit the `$algo$...` PHC mold but still have
    # unmistakable shapes. We check each in turn before falling through
    # to the generic length-based step

    # NetNTLMv1 / NetNTLMv2 — the dominant outputs of AD pentest
    # tools like Responder, secretsdump, ntlmrelayx, and Inveigh.
    # They are NOT hashes in the "irreversible function" sense —
    # they are challenge-response records — but every beginner who
    # runs their first AD lab pastes one of these into a hash
    # identifier. The literal `::` (an empty second field, where the
    # LM-hash used to live) is the structural giveaway. We test v2
    # FIRST because v2's hmac field at index 4 is 32 hex chars while
    # v1's nthash at the same index is 48 — so if we tested v1 first
    # we would still match v2 inputs at parts[3] (also 48 in v2's
    # case for the challenge length in some encodings)
    if "::" in text and text.count(":") >= 4:
        parts = text.split(":")
        # NetNTLMv2 layout:
        #   user :: domain : challenge : hmac(32 hex) : blob(>=32 hex)
        # The hmac at parts[4] is exactly 32 hex chars — that single
        # property is enough to disambiguate v2 from v1
        if (len(parts) >= 6 and len(parts[4]) == 32 and _is_hex(parts[4])):
            confidence_score = 0.85
            return [
                HashCandidate(
                    algorithm = "NetNTLMv2",
                    confidence = confidence_score,
                    reason =
                    "user::domain:challenge:hmac(32 hex):blob shape",
                    hashcat_mode = HASHCAT_MODES.get(algorithm),
                    crack_difficulty = DIFFICULTY_MAP[algorithm],
                )
            ]
        # NetNTLMv1 layout:
        #   user :: domain : lmhash(48 hex) : nthash(48 hex) : challenge
        # The lmhash at parts[3] is exactly 48 hex chars
        if (len(parts) >= 6 and len(parts[3]) == 48 and _is_hex(parts[3])):
            confidence_score = 0.85
            return [
                HashCandidate(
                    algorithm = "NetNTLMv1",
                    confidence = confidence_score,
                    reason =
                    "user::domain:lm(48 hex):nt(48 hex):challenge shape",
                    hashcat_mode = HASHCAT_MODES.get(algorithm),
                    crack_difficulty = DIFFICULTY_MAP[algorithm],
                )
            ]

    # MySQL5 — literal `*` + 40 uppercase hex chars
    if _is_mysql5(text):
        confidence_score = 0.85
        return [
            HashCandidate(
                algorithm = "MySQL5",
                confidence = confidence_score,
                reason =
                "starts with `*` followed by 40 uppercase hex chars",
                hashcat_mode = HASHCAT_MODES.get(algorithm),
                crack_difficulty = DIFFICULTY_MAP[algorithm],
            )
        ]

    # Traditional 13-char DES crypt — legacy /etc/passwd format
    # with no prefix at all. We report MEDIUM (not HIGH) because the
    # 13-char `./0-9A-Za-z` shape isn't fully unique to DES crypt
    if _is_descrypt(text):
        confidence_score = 0.85
        return [
            HashCandidate(
                algorithm = "DES crypt",
                confidence = confidence_score,
                reason =
                "13 chars in `./0-9A-Za-z` — legacy /etc/passwd format",
                hashcat_mode = HASHCAT_MODES.get(algorithm),
                crack_difficulty = DIFFICULTY_MAP[algorithm],
            )
        ]

    # ----- Step 3: length + hex charset -----
    if _is_hex(text):
        algorithms = HEX_LENGTH_RULES.get(len(text), [])
        candidates: list[HashCandidate] = []
        for index, algorithm in enumerate(algorithms):
            # The first listed algorithm for each length is the modern
            # default and gets MEDIUM confidence. The rest are still
            # possible but less common in 2026 — LOW confidence
            confidence_score = 0.55 / (index + 1) 
            label = (
                "most likely candidate at this length"
                if index == 0 else "also possible at this length"
            )
            candidates.append(
                HashCandidate(
                    algorithm = algorithm,
                    confidence = confidence_score,
                    reason = f"{len(text)} hex chars — {label}",
                    hashcat_mode = HASHCAT_MODES.get(algorithm),
                    crack_difficulty = DIFFICULTY_MAP[algorithm],
                )
            )
        return candidates

    # ----- Step 4: generic PHC string fallback -----
    # If the input starts with `$<name>$...` and <name> looks like a
    # plausible algorithm identifier, it is almost certainly a PHC
    # string from an algorithm we do not have a specific rule for.
    # Passlib alone ships ~30 PHC encodings; our PREFIX_RULES table
    # covers only the most common 20-or-so. Reporting it as a generic
    # PHC string with the extracted algorithm name is strictly better
    # than silence, and the LOW confidence label is honest about not
    # having a specific rule to confirm the algorithm
    if text.startswith("$"):
        # Drop the leading `$`, then look for the second `$` that
        # closes the algorithm-name field. If there's no second `$`,
        # this isn't a PHC string at all, just a string that happens
        # to start with `$` — fall through
        rest = text[1 :]
        if "$" in rest:
            algo_name = rest.split("$", 1)[0]
            # The PHC spec restricts algorithm IDs to alphanumeric
            # plus `-` and `_`. We accept exactly that charset and
            # reject anything weirder — anything containing spaces,
            # punctuation, etc. is almost certainly not a real PHC
            # string and we'd rather stay silent than make up a name
            if algo_name and all(c.isalnum() or c in "-_"
                                 for c in algo_name):
                confidence_score = 0.4
                return [
                    HashCandidate(
                        algorithm = f"PHC string ({algo_name})",
                        confidence = confidence_score,
                        reason =
                        f"`${algo_name}$...` shape — generic PHC, no specific rule",
                        hashcat_mode = HASHCAT_MODES.get(algorithm),
                        crack_difficulty = DIFFICULTY_MAP[algorithm],
                    )
                ]

    # ----- Step 5: not-a-hash shape hints -----
    # Beginners often paste JWTs or base64 blobs into a hash
    # identifier — they are auth tokens, not hashes, but the user
    # may not know that yet. Returning a short shape-hint at LOW
    # confidence is more educational than a silent no-match: the
    # user finds out WHAT they pasted and that this tool is not
    # going to crack it for them
    confidence_score = 0.3
    if text.startswith("eyJ"):
        # JWTs always begin with `eyJ` because their JSON header
        # `{"alg":...}` base64-encodes to a string starting with
        # those three characters (`{"` → base64 → `eyI`/`eyJ`)
        return [
            HashCandidate(
                algorithm = "JWT (not a hash)",
                confidence = confidence_score,
                reason =
                "leading `eyJ` is base64 of `{\"` — JWT, not a hash",
                crack_difficulty = DIFFICULTY_MAP.get(algorithm, "trivial"),
            )
        ]
    if text.startswith("http://") or text.startswith("https://"):
        return [
            HashCandidate(
                algorithm = "URL (not a hash)",
                confidence= confidence_score,
                reason = "starts with http(s)://",
                crack_difficulty = DIFFICULTY_MAP.get(algorithm, "trivial"),
            )
        ]
    if text.startswith("0x"):
        return [
            HashCandidate(
                algorithm = "Simple hex (not a hash)",
                confidence= confidence_score,
                reason = "starts with 0x prefix",
                crack_difficulty = DIFFICULTY_MAP.get(algorithm, "trivial"),
            )
        ]
    if any(c in text for c in "+/=") and len(text) > 8:
        # Hex hashes NEVER contain `+`, `/`, or `=`. If our input
        # does, it is almost certainly base64-encoded data of some
        # kind. The `> 8` length floor avoids flagging short
        # strings like "a+b=c" as base64
        return [
            HashCandidate(
                algorithm = "Base64 blob (not a hash)",
                confidence = confidence_score,
                reason = "contains base64-only chars (`+`, `/`, `=`)",
                crack_difficulty = DIFFICULTY_MAP.get(algorithm, "trivial"),
            )
        ]
    if all(c in BASE32_CHARS for c in text):
        return [
            HashCandidate(
                algorithm = "Base32 blob (not a hash)",
                confidence= confidence_score,
                reason = "contains base32 only chars (only uppsercase letters and digits 2-7)",
                crack_difficulty = DIFFICULTY_MAP.get(algorithm, "trivial"),
            )
        ]
    if all(c in BASE58_CHARS for c in text):
        return [
            HashCandidate(
                algorithm = "Base58 blob (not a hash)",
                confidence= confidence_score,
                reason = "contains base58 only chars",
                crack_difficulty = DIFFICULTY_MAP.get(algorithm, "trivial"),
            )
        ]
    
        

    # ----- Step 6: nothing matched -----
    # If we got here, the input has no known prefix, no special
    # shape, no hex length we recognize, no PHC-string shape, and
    # no obvious not-a-hash shape either. Returning an empty list
    # is better than returning bad guesses — the CLI prints a
    # clean "could not identify" message instead
    return []

# =============================================================================
# split() - identifies what each field of the string represents
# =============================================================================

def split(text: str) -> list[tuple[str, str]]:
    already_completed = {
        "username": 0,
        "hash": 0,
        "salt": 0,
    }
    split_results = []
    fields = text.split(":")
    for index, field in enumerate(fields):
        candidates = identify(field)
        if already_completed["hash"] == 0 and len(candidates) >= 1 and not "not a hash" in candidates[0].algorithm:
            split_results.append(("hash", field))
            already_completed["hash"] = 1
        elif already_completed["salt"] == 0 and (all(c in BASE64_CHARS for c in field) 
                and (len(field) == 22 or len(field) == 24)) or (all(c in HEX_CHARSET for c in field) and len(field) == 32):
            split_results.append(("salt", field))
            already_completed["salt"] = 1
        elif already_completed["username"] == 0 and all(c in USERNAME_CHARS for c in field):
            split_results.append(("username", field))
            already_completed["username"] = 1
        else:
            split_results.append(("garbage", field))
    
    return split_results
            
   

# =============================================================================
# CLI — argparse + a rich table
# =============================================================================


def _build_argument_parser() -> argparse.ArgumentParser:
    """
    Construct the argparse parser used by main()

    Pulled out into its own function so tests can call it without
    actually running the CLI. Each argument is documented inline
    """
    parser = argparse.ArgumentParser(
        prog = "hashid",
        description = (
            "Identify a hash string by prefix, length, and charset. "
            "Returns ranked candidates with confidence and reasoning."
        ),
    )
    parser.add_argument(
        "hash",
        nargs = "?",
        help =
        "The hash string to identify (wrap in single quotes if it contains $).",
    )
    parser.add_argument(
        "--top",
        "-n",
        type = int,
        default = 5,
        help = "Show at most this many candidates (default: 5).",
    )
    parser.add_argument(
        "--json",
        action = "store_true",
        help = "Get JSON formatted output instead of a table.",
    )
    parser.add_argument(
        "--file",
        type = Path,
        help = "The path of the file which will have its hashes identified",
    )
    parser.add_argument(
        "--split",
        type = str,
        help = "Takes a string such as: 'username:hash:salt' and returns a table identifying which field is which (since they can be in whatever order)",
    )
    return parser

def _render_split_table(
    raw_input: str,
    split_results: list[tuple[str, str]],
    console: Console,
) -> None:
    table = Table(
        title = f"Classification of: {raw_input.strip()} fields",
    )
    for result in split_results:
        table.add_column(result[0])
    table.add_row(split_results[0][1], split_results[1][1], split_results[2][1])
    
    console.print(table)
        


def _render_table(
    raw_input: str,
    candidates: list[HashCandidate],
    console: Console,
) -> None:
    """
    Print a rich Table showing the identified candidates

    A Table is a bordered grid. We give it three columns: algorithm,
    confidence (color-coded), and reason
    """
    table = Table(
        title = f"Candidates for: {raw_input.strip()}",
        title_style = "bold cyan",
        show_lines = False,
    )
    table.add_column("algorithm", style = "bold white", no_wrap = True)
    table.add_column("confidence", no_wrap = True)
    table.add_column("reason", style = "dim")
    table.add_column("hashcat mode")
    table.add_column("crack difficulty")

    # Color confidence levels so the eye can scan them quickly.
    # green → yellow → cyan is a gradient that reads "strong, weaker,
    # weakest" without ever colliding with red, which is reserved for
    # the no-match error message printed elsewhere in main(). Painting
    # "low" in red would make three weak-but-valid guesses look like
    # three errors at a glance — broken visual hierarchy
    for candidate in candidates:
        if candidate.confidence > 0.8:
            color = "green"
        elif candidate.confidence > 0.5 and candidate.confidence < 0.8:
            color = "yellow"
        else:
            color = "cyan"
        table.add_row(
            candidate.algorithm,
            f"[{color}]{candidate.confidence}[/{color}]",
            candidate.reason,
            f"{candidate.hashcat_mode}" if HASHCAT_MODES.get(candidate.algorithm) is not None else "Unknown",
            candidate.crack_difficulty,
            
        )
    console.print(table)


def main() -> int:
    """
    CLI entry point — return an exit code (0 = ok, 1 = nothing found)

    Wrapping the body in a function (instead of running at module
    import time) means the test suite can import this module without
    accidentally executing the CLI
    """
    parser = _build_argument_parser()
    args = parser.parse_args()
    console = Console()
    
    
    raw_lines: list[str] = []

    if args.hash is not None:
        raw_lines = [args.hash]
    elif args.split is not None:
        raw_lines = [args.split]
    elif args.file is not None:
        raw_lines = args.file.read_text().splitlines()
    elif not sys.stdin.isatty():
        raw_lines = sys.stdin.read().splitlines()
    else:
        console.print("[red]Error: No input provided.[/red] Please provide a hash, use --file, or pipe data in.")
        return 1

    # Strip whitespace and drop entirely blank lines to prevent crashes on empty inputs
    lines = [line.strip() for line in raw_lines if line.strip()]
    if not lines:
        return 0

    results = []
    
    if args.split is not None:
        for line in lines:
            split_result = split(line)
            _render_split_table(line, split_result, console)
        exit_code = 1
    else:
        
        for raw_hash in lines:
            candidates = identify(raw_hash)
            trimmed = candidates[: args.top]
            results.append({
                "hash": raw_hash,
                "candidates": trimmed,
                "dict_candidates": [asdict(c) for c in trimmed] # Pre-build JSON format
            })

        # Track exit code (if a single hash was queried but found nothing, return 1)
        exit_code = 1 if (len(results) == 1 and not results[0]["candidates"]) else 0

        if args.json:
            # Build the exact JSON structure we want
            json_data = [{"hash": r["hash"], "candidates": r["dict_candidates"]} for r in results]
            
            # If it's a single item, unwrap it from the list so the JSON looks cleaner
            if len(json_data) == 1:
                console.print_json(data=json_data[0], indent=2)
            else:
                console.print_json(data=json_data, indent=2)

        else:
            if len(results) == 1:
                # Single-item -> rich table
                res = results[0]
                if not res["candidates"]:
                    console.print(
                        "[red]No identification possible.[/red] "
                        "Input did not match any known prefix, special format, "
                        "or hex length."
                    )
                else:
                    _render_table(res["hash"], res["candidates"], console)
                    if res["candidates"][0].hashcat_mode is not None:
                        console.print(
                            f"\n[dim]Next step: try the matching cracker mode: hashcat -m {res["candidates"][0].hashcat_mode} -a 0 '{res["hash"]}' wordlist.txt"
                            "(see ../../beginner/hash-cracker).[/dim]"
                        )
            else:
                # Multi-item -> textual representation
                for res in results:
                    print(f"{res['hash']}:")
                    if not res["candidates"]:
                        print("  No identification possible.")
                    for candidate in res["candidates"]:
                        print(f"  Algorithm: {candidate.algorithm}, Confidence: {candidate.confidence}, Reason: {candidate.reason}")
                    print()
                    if len(res["candidates"]) > 0 and res["candidates"][0].hashcat_mode is not None:
                        console.print(
                            f"\n[dim]Next step: try the matching cracker mode: hashcat -m {res['candidates'][0].hashcat_mode} -a 0 '{res['hash']}' wordlist.txt \n"
                            "(see ../../beginner/hash-cracker).[/dim]"
                        )

    return exit_code


# Standard "if invoked directly as a script" guard — lets the file be
# imported by tests without firing main()
if __name__ == "__main__":
    sys.exit(main())
