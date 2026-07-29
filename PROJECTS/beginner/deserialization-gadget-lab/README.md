# rube

A Ruby object-deserialization security lab.

A gadget chain is a Rube Goldberg machine. One untrusted blob goes in, a dozen
unrelated standard-library methods knock each other over, and code execution falls out
the far end. This project builds the machine, then builds the thing that stops it.

## Why this exists

`Marshal.load` on untrusted input is arbitrary code execution. So is `YAML.unsafe_load`,
`JSON.load` with additions enabled, and `Oj.load` in its default mode. This is not a Ruby
quirk. It is the same class of bug as Java deserialization, PHP POP chains, and Python
pickle, and it sits at CWE-502 in the CISA Known Exploited Vulnerabilities catalog with a
**34.8% known-ransomware rate against a 20.1% baseline** across the catalog as a whole.

Most write-ups on this topic teach the exploit. Fewer teach why the obvious defense does
not work. This one does both, because the second half is where the actual lesson lives:

**You cannot make `Marshal.load` safe with an allowlist.** The `proc` you pass runs in
`r_post_proc`, which `marshal.c` invokes *after* `load_funcall(... s_mload ...)`. By the
time your allowlist sees the object, `marshal_load` has already run. The pattern widely
copied off Stack Overflow is a post-mortem, not a veto.

**Psych's allowlist genuinely is a veto** — for exactly one reason. It checks the tag
*before* revival, where Marshal checks the object *after* construction. Identical intent,
opposite outcome, decided entirely by where the check sits.

## Status

All six pieces are built and tested.

- **Marshal stream parser** — parses the binary format, extracts referenced class names
  and gadget sinks, and validates structure, all without ever calling `Marshal.load`.
  Rejects truncated streams, unsupported versions, unknown tags, out-of-bounds object
  links and symlinks, oversized fixnum widths, trailing bytes, and excessive nesting.
- **Version-compatibility matrix** — probes six pinned Ruby images and reports where the
  published git gadget and the ERB `@_init` guard actually change.
- **Reflection-based gadget scanner** — walks `ObjectSpace` for auto-invoked methods and
  classifies them by whether `Marshal.load` can reach them. It counts every error it
  swallows, names the site, and treats a method it could not analyse as reachable rather
  than inert, so under-reporting is visible instead of silent.
- **Payload builder** — version-scoped chains carrying their own affected ranges.
- **Vulnerable containerized target** — a Sinatra app with one endpoint that loads a
  session cookie and one that inspects it first.
- **Boundary detector** — the defensive layer, with an explicit written statement of what
  it cannot do.

## Requirements

Ruby **3.4 or newer**. That floor is measured, not picked for tidiness.

Ruby changed `Marshal.load` between 3.3 and 3.4. Through 3.3, any byte in a bignum's sign
position is accepted and anything that is not `-` is read as positive. From 3.4 onward the
same stream raises `ArgumentError: invalid Bignum sign`:

| sign byte | 3.2.11 | 3.3.12 | 3.4.10 | 4.0.6 |
|---|---|---|---|---|
| `+` and `-` | accept | accept | accept | accept |
| `!`, `\x00`, `\xFF`, `0` | accept | accept | **reject** | **reject** |

rube's parser accepts `+` and `-` only, so it models 3.4 and newer. Run it on 3.3 and it
disagrees with the interpreter it exists to model on four of those six bytes. A stream
inspector that disagrees with the loader it guards is not worth shipping, so the floor sits
where the agreement starts. `just package` re-proves this in both directions on every run:
on the floor image Ruby and the parser agree, one version below it they diverge.

## Installation

rube is not published to rubygems.org. Build it from this checkout and install the artifact:

```
just build
gem install --local tmp/build/rube-0.1.0.gem
```

The gem carries `lib/`, the README, the changelog, and the license. Nothing else. The
vulnerable target, the adversarial corpus, the gate scripts, and the research notes stay in
the repository, and `just package` fails if any of them turn up inside a built artifact.

## Usage

```ruby
require "rube"

payload = Marshal.dump(Gem::Requirement.new(">= 0"))
result = Rube::Marshal::Parser.new(payload).parse

result.class_names
# => ["Gem::Requirement", "Gem::Version"]

result.sinks.map { |s| "#{s.class_name}##{s.sink_method}" }
# => ["Gem::Requirement#marshal_load", "Gem::Version#marshal_load"]
```

`Parser.new` enforces `Rube::Marshal::Limits.new` unless you say otherwise. Every ceiling
is opt-out, never opt-in — pass `limits: Rube::Marshal::Limits.permissive` if you are doing
forensics on a stream you already trust and want it parsed whole.

To make a decision rather than inspect a stream, use the detector, which applies a policy
and hands back a frozen snapshot:

```ruby
detector = Rube::Marshal::BoundaryDetector.new(allowed_class_names: %w[Hash String])
decision = detector.inspect_stream(untrusted_bytes)

decision.blocked?    # => true
decision.reason      # => "stream reaches Gem::Requirement#marshal_load during load, ..."
```

A decision is in exactly one of three states, and `proceed?` is the only one that gates a
load:

```ruby
Marshal.load(decision.snapshot) if decision.proceed?
```

`proceed?` means the policy found no violation. `blocked?` means it found one and refused.
`observed?` is the third state, and it exists because `POLICY_OBSERVE_AND_LOG` is
non-blocking by design: a violation was found, reported, and deliberately not enforced. Such
a decision still carries its snapshot, so a caller running in monitoring mode opts in by
naming that state out loud:

```ruby
Marshal.load(decision.snapshot) if decision.proceed? || decision.observed?
```

There is no `accepted?`. The question "did the policy permit this" and the question "is
this stream free of violations" have different answers under observe-and-log, and one
predicate cannot answer both.

Read `Rube::Marshal::BoundaryDetector::LIMITATION_NOTICE` before relying on `proceed?`.
A stream that proceeds is not a safe one, and the notice says so in detail.

Nothing above instantiates a class, calls a constructor, or invokes `Marshal.load`.

## Development

Everything runs in Docker against a pinned Ruby.

```
just test       run the minitest suites
just control    run the negative controls
just check      both
just corpus     print every adversarial corpus case and its verdict
just scan       run the gadget scanner over loaded modules
just matrix     probe six pinned Ruby images and render the compatibility matrix
just exploit    prove the chain fires on a vulnerable image and is blocked on a patched one
just target     stand up the vulnerable app and attack it over HTTP
just detector   prove the defensive layer rejects the payload the target executes
just package    build the gem, audit what shipped, install it, prove the version floor
just gate       everything above, in order
just build      build the gem with --strict into tmp/build
just manifest   list exactly what would ship in the .gem
```

`just package` also audits an artifact you already have, which is how you check that a gem
on disk still matches the source it claims to be built from:

```
just package tmp/build/rube-0.1.0.gem
```

## A note on the object-link index

Ruby's Marshal format documentation states that object links are one-indexed. **They are
zero-indexed.** A self-referential array dumps as `04 08 5b 06 40 00`, where the trailing
`00` is a link to the outermost object at index 0. The parser is written against the
observed bytes, not the documentation.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
