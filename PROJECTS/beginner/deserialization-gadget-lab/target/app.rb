# ©AngelaMos | 2026
# app.rb

require "sinatra/base"
require "base64"
require "erb"
require "rube"

module Rube
  module Target
    COOKIE_NAME = "session_state"
    CANARY_PATH = "/tmp/rube-canary"

    STATUS_OK = 200
    STATUS_BAD_REQUEST = 400

    CONTENT_TYPE = "text/plain"

    ALLOWED_CLASSES = %w[Hash String Symbol Integer Array].freeze
    BENIGN_TEMPLATE = "hello"

    REJECTED_SINK = "rejected: payload reaches %s#%s before any allowlist can run"
    REJECTED_CLASS = "rejected: payload references %s"
    RENDERED = "rendered template for %s"
    NO_SESSION = "no session cookie"
    MALFORMED = "rejected: malformed stream (%s)"

    class App < Sinatra::Base
      set :host_authorization, permitted_hosts: []

      get "/" do
        content_type CONTENT_TYPE
        [
          "rube target",
          "erb #{Gem::Specification.find_all_by_name('erb').map(&:version).max}",
          "ruby #{RUBY_VERSION}",
          "",
          "POST /session      issue a benign session cookie",
          "GET  /render       deserialize and compile the session template (VULNERABLE)",
          "GET  /render/safe  inspect the stream before deserializing (DEFENDED)",
          "GET  /canary       report whether the canary file exists"
        ].join("\n")
      end

      post "/session" do
        state = { user: "guest", template: BENIGN_TEMPLATE }
        response.set_cookie(COOKIE_NAME, value: encode(state), path: "/")
        content_type CONTENT_TYPE
        "session issued"
      end

      get "/render" do
        content_type CONTENT_TYPE
        blob = decode(request.cookies[COOKIE_NAME])
        halt STATUS_BAD_REQUEST, NO_SESSION unless blob

        state = ::Marshal.load(blob)
        compile(state)
      end

      get "/render/safe" do
        content_type CONTENT_TYPE
        blob = decode(request.cookies[COOKIE_NAME])
        halt STATUS_BAD_REQUEST, NO_SESSION unless blob

        verdict = inspect_stream(blob)
        halt STATUS_BAD_REQUEST, verdict if verdict

        compile(::Marshal.load(blob))
      end

      get "/canary" do
        content_type CONTENT_TYPE
        File.exist?(CANARY_PATH) ? File.read(CANARY_PATH) : "absent"
      end

      private

      def encode(state)
        Base64.strict_encode64(::Marshal.dump(state))
      end

      def decode(raw)
        return nil unless raw

        Base64.strict_decode64(raw)
      rescue ArgumentError
        nil
      end

      def compile(state)
        template = state[:template]
        template.def_method(Module.new, "render_it") if template.respond_to?(:def_method)
        format(RENDERED, state[:user])
      end

      def inspect_stream(blob)
        result = Rube::Marshal::Parser.new(blob).parse

        sink = result.sinks.first
        return format(REJECTED_SINK, sink.class_name, sink.sink_method) if sink

        unknown = result.class_names.reject { |name| ALLOWED_CLASSES.include?(name) }
        return format(REJECTED_CLASS, unknown.join(", ")) unless unknown.empty?

        nil
      rescue Rube::Marshal::StreamError => e
        format(MALFORMED, e.class.name.split("::").last)
      end
    end
  end
end
