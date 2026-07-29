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

    DETECTOR = Rube::Marshal::BoundaryDetector.new(
      policy: Rube::Marshal::BoundaryDetector::POLICY_STRICT_ALLOWLIST,
      allowed_class_names: ALLOWED_CLASSES,
      limits: Rube::Marshal::Limits.new
    )

    REJECTED = "rejected: %s"
    RENDERED = "rendered template for %s"
    NO_SESSION = "no session cookie"

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

        decision = DETECTOR.inspect_stream(blob)
        halt STATUS_BAD_REQUEST, format(REJECTED, decision.reason) if decision.rejected?

        compile(::Marshal.load(decision.snapshot))
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
    end
  end
end
