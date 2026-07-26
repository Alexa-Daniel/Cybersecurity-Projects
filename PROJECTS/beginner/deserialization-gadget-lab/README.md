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

Under construction. What exists and is tested:

- **Marshal stream parser** — parses the binary format, extracts referenced class names
  and gadget sinks, and validates structure, all without ever calling `Marshal.load`.
  Rejects truncated streams, unsupported versions, unknown tags, out-of-bounds object
  links and symlinks, oversized fixnum widths, trailing bytes, and excessive nesting.

Planned: version-compatibility matrix, reflection-based gadget scanner, payload builder,
a deliberately vulnerable containerized target, and the defensive layer.

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

Nothing above instantiates a class, calls a constructor, or invokes `Marshal.load`.

## Development

Everything runs in Docker against a pinned Ruby.

```
just test       run the parser suite
just control    run the negative controls
just check      both
just build      build the gem with --strict
just manifest   list exactly what would ship in the .gem
```

## A note on the object-link index

Ruby's Marshal format documentation states that object links are one-indexed. **They are
zero-indexed.** A self-referential array dumps as `04 08 5b 06 40 00`, where the trailing
`00` is a link to the outermost object at index 0. The parser is written against the
observed bytes, not the documentation.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
