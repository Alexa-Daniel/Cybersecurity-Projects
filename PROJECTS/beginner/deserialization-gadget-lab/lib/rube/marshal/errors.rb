# ©AngelaMos | 2026
# errors.rb

module Rube
  module Marshal
    class StreamError < StandardError; end

    class TruncatedStreamError < StreamError; end

    class UnsupportedVersionError < StreamError; end

    class UnknownTagError < StreamError; end

    class TrailingBytesError < StreamError; end

    class InvalidLinkError < StreamError; end

    class DepthLimitError < StreamError; end
  end
end
