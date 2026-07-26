# ©AngelaMos | 2026
# constants.rb

module Rube
  module Marshal
    module Constants
      MAJOR_VERSION = 4
      MINOR_VERSION = 8
      HEADER_LENGTH = 2

      TAG_NIL = "0"
      TAG_TRUE = "T"
      TAG_FALSE = "F"
      TAG_FIXNUM = "i"
      TAG_BIGNUM = "l"
      TAG_FLOAT = "f"
      TAG_STRING = '"'
      TAG_SYMBOL = ":"
      TAG_SYMLINK = ";"
      TAG_OBJECT_LINK = "@"
      TAG_ARRAY = "["
      TAG_HASH = "{"
      TAG_HASH_DEFAULT = "}"
      TAG_REGEXP = "/"
      TAG_OBJECT = "o"
      TAG_USERDEF = "u"
      TAG_USERMARSHAL = "U"
      TAG_USERCLASS = "C"
      TAG_EXTENDED = "e"
      TAG_CLASS = "c"
      TAG_MODULE = "m"
      TAG_MODULE_OLD = "M"
      TAG_STRUCT = "S"
      TAG_DATA = "d"
      TAG_IVAR = "I"

      BIGNUM_SIGN_POSITIVE = "+"
      BIGNUM_SIGN_NEGATIVE = "-"
      BIGNUM_WORD_BYTES = 2

      FIXNUM_INLINE_OFFSET = 5
      FIXNUM_MAX_INLINE = 4
      FIXNUM_MIN_INLINE = -4
      FIXNUM_MAX_WIDTH = 4

      BYTE_SIGN_THRESHOLD = 128
      BYTE_MODULUS = 256
      BITS_PER_BYTE = 8

      DEFAULT_MAX_DEPTH = 256

      SINK_TAGS = [TAG_USERDEF, TAG_USERMARSHAL, TAG_DATA].freeze

      SINK_METHODS = {
        TAG_USERDEF => "_load",
        TAG_USERMARSHAL => "marshal_load",
        TAG_DATA => "_load_data"
      }.freeze

      GATED_SINK_TAGS = [TAG_USERDEF, TAG_USERMARSHAL].freeze
    end
  end
end
