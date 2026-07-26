# ©AngelaMos | 2026
# control_check.rb

require_relative "test_helper"

Pair = Struct.new(:x, :y)

puts "=== control 1: does the TracePoint oracle actually fire on a real Marshal.load ==="
fired = false
tracer = TracePoint.new(:call, :c_call) do |tp|
  fired = true if tp.method_id == :load && tp.self.equal?(Marshal)
end
tracer.enable { Marshal.load(Marshal.dump([1, 2])) }
puts fired ? "  FIRED - oracle is live, the never-calls-load test is meaningful" : "  DID NOT FIRE - oracle is broken, that test proves nothing"

puts
puts "=== control 2: object link index actually present in the stream ==="
cyclic = []
cyclic << cyclic
blob = Marshal.dump(cyclic)
puts "  bytes: #{blob.bytes.map { |b| format('%02x', b) }.join(' ')}"
puts "  ascii: #{blob.inspect}"
link = Rube::Marshal::Parser.new(blob).parse.root.children.first
puts "  parsed link index: #{link.value} (must be 0, docs claim 1)"

puts
puts "=== control 3: broad corpus round-trip, parser vs Marshal ground truth ==="
shared = "shared"
aliased = [shared, shared]
cyclic_hash = {}
cyclic_hash[:self] = cyclic_hash
deep = [1]
20.times { deep = [deep] }

corpus = [
  nil, true, false,
  0, 1, -1, 122, 123, -123, -124, 255, -256, 65_536, -65_536,
  1_073_741_823, -1_073_741_824, 2**70, -(2**70), 2**200,
  0.0, -0.0, 3.14, Float::INFINITY, -Float::INFINITY,
  "", "str", "\x00\xff binary".b, "unicode é中",
  :sym, :"with spaces", :marshal_load,
  [], {}, [1, [2, [3, [4]]]], { a: { b: { c: 1 } } },
  (1..5).to_a, Pair.new(1, 2), Pair.new(nil, [1, 2]),
  Object.new, Time.now, /regex/i, //mx, String, Comparable, Rube,
  aliased, cyclic_hash, deep,
  { "mixed" => [1, :two, 3.0, nil, true] },
  Hash.new(0).tap { |h| h[:k] = 1 },
  Gem::Requirement.new(">= 0"), Gem::Version.new("1.2.3")
]
ok = 0
corpus.each do |item|
  blob = Marshal.dump(item)
  result = Rube::Marshal::Parser.new(blob).parse
  raise "no root for #{item.inspect}" unless result.root

  ok += 1
rescue StandardError => e
  puts "  FAIL #{item.class}: #{e.class}: #{e.message}"
end
puts "  #{ok}/#{corpus.length} parsed without Marshal.load"

puts
puts "=== control 4: mutation - break the link bounds check, does a test catch it ==="
puts "  (verified manually below by feeding an out-of-range link)"
begin
  Rube::Marshal::Parser.new("\x04\x08[\x06@\x63").parse
  puts "  NOT CAUGHT - bounds check is dead"
rescue Rube::Marshal::InvalidLinkError => e
  puts "  CAUGHT: #{e.message}"
end

puts
puts "=== control 5: real gadget-shaped payload, class names extracted, nothing built ==="
payload = Marshal.dump(Gem::Requirement.new(">= 0"))
result = Rube::Marshal::Parser.new(payload).parse
puts "  classes: #{result.class_names.inspect}"
puts "  sinks:   #{result.sinks.map { |s| "#{s.class_name}##{s.sink_method}" }.inspect}"
puts "  gated:   #{result.gated_sinks.map(&:class_name).inspect}"

puts
puts "=== control 6: M1 stream parsing and M3 reflection must agree ==="
puts "  Two independent routes to the same fact. The parser reads bytes off a"
puts "  payload; the scanner walks the live class graph. Neither consults the"
puts "  other. If they disagree, one of them is wrong."
from_stream = result.gated_sinks.map { |s| "#{s.class_name}##{s.sink_method}" }.uniq.sort
scanned = Rube::Scanner.new(namespace: "Gem").scan.gated.map(&:to_s)
from_reflection = from_stream.select { |entry| scanned.include?(entry) }.sort
puts "  parser  (M1): #{from_stream.inspect}"
puts "  scanner (M3): #{scanned.inspect}"
if from_stream == from_reflection && !from_stream.empty?
  puts "  AGREE - every sink the parser found in the payload is a sink the scanner"
  puts "          independently located in the class graph"
else
  puts "  DISAGREE - parser found #{(from_stream - from_reflection).inspect} that reflection did not"
end

puts
puts "=== control 7: scanner precision, it must not report everything ==="
full = Rube::Scanner.new.scan
ratio = (full.candidates.length.to_f / full.scanned_modules * 100).round(1)
puts "  #{full.scanned_modules} modules scanned -> #{full.candidates.length} candidates (#{ratio}% hit rate)"
puts "  gated: #{full.gated.length}"
puts(ratio < 100 ? "  PASS - scanner discriminates" : "  FAIL - scanner reports every module, it is not filtering")
puts
puts "  NOTE: ObjectSpace only sees loaded code. #{full.scanned_modules} modules is a bare"
puts "  Ruby with RubyGems. A booted Rails app eager-loaded is several times that."
puts "  Coverage is bounded by what has been required, and that is a real limit."
