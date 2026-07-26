# ©AngelaMos | 2026
# parser.rb

module Rube
  module Marshal
    class Parser
      include Constants

      def initialize(source, max_depth: DEFAULT_MAX_DEPTH)
        @source = source.to_s.dup.force_encoding(Encoding::BINARY)
        @max_depth = max_depth
        @position = 0
        @symbols = []
        @objects = []
      end

      def parse
        read_header
        root = read_value(1)
        raise TrailingBytesError, "#{remaining} unread bytes" unless remaining.zero?

        Result.new(root)
      end

      private

      attr_reader :source, :max_depth, :symbols, :objects

      def remaining
        source.bytesize - @position
      end

      def take(count)
        raise MalformedCountError, "negative byte count #{count}" if count.negative?
        raise TruncatedStreamError, "wanted #{count} bytes, had #{remaining}" if count > remaining

        slice = source.byteslice(@position, count)
        @position += count
        slice
      end

      def read_count(role)
        value = read_fixnum
        raise MalformedCountError, "negative #{role} count #{value}" if value.negative?

        value
      end

      def take_byte
        take(1).unpack1("C")
      end

      def take_signed_byte
        byte = take_byte
        byte >= BYTE_SIGN_THRESHOLD ? byte - BYTE_MODULUS : byte
      end

      def read_header
        header = take(HEADER_LENGTH)
        major, minor = header.unpack("CC")
        return if major == MAJOR_VERSION && minor <= MINOR_VERSION

        raise UnsupportedVersionError, "stream declares #{major}.#{minor}"
      end

      def read_fixnum
        marker = take_signed_byte
        return 0 if marker.zero?
        return marker - FIXNUM_INLINE_OFFSET if marker > FIXNUM_MAX_INLINE
        return marker + FIXNUM_INLINE_OFFSET if marker < FIXNUM_MIN_INLINE

        width = marker.abs
        raise TruncatedStreamError, "fixnum width #{width}" if width > FIXNUM_MAX_WIDTH

        value = little_endian(take(width))
        marker.negative? ? value - (1 << (BITS_PER_BYTE * width)) : value
      end

      def little_endian(bytes)
        bytes.each_byte.with_index.sum { |byte, index| byte << (BITS_PER_BYTE * index) }
      end

      def read_counted_bytes
        take(read_count(ROLE_LENGTH))
      end

      def register(node)
        objects << node
        node
      end

      def read_value(depth)
        raise DepthLimitError, "exceeded depth #{max_depth}" if depth > max_depth

        tag = take(1)

        case tag
        when TAG_NIL then Node.new(type: :nil, tag: tag)
        when TAG_TRUE then Node.new(type: :boolean, tag: tag, value: true)
        when TAG_FALSE then Node.new(type: :boolean, tag: tag, value: false)
        when TAG_FIXNUM then Node.new(type: :fixnum, tag: tag, value: read_fixnum)
        when TAG_SYMBOL then read_symbol(tag)
        when TAG_SYMLINK then read_symlink(tag)
        when TAG_OBJECT_LINK then read_object_link(tag)
        when TAG_BIGNUM then register(read_bignum(tag))
        when TAG_FLOAT then register(read_float(tag))
        when TAG_STRING then register(read_string(tag))
        when TAG_REGEXP then register(read_regexp(tag))
        when TAG_ARRAY then read_array(tag, depth)
        when TAG_HASH, TAG_HASH_DEFAULT then read_hash(tag, depth)
        when TAG_IVAR then read_ivar(tag, depth)
        when TAG_OBJECT then read_object(tag, depth)
        when TAG_STRUCT then read_struct(tag, depth)
        when TAG_USERDEF then register(read_userdef(tag))
        when TAG_USERMARSHAL then read_usermarshal(tag, depth)
        when TAG_DATA then read_wrapped(tag, :data, depth)
        when TAG_USERCLASS then read_wrapped(tag, :user_class, depth)
        when TAG_EXTENDED then read_wrapped(tag, :extended, depth)
        when TAG_CLASS then register(read_named(tag, :class))
        when TAG_MODULE, TAG_MODULE_OLD then register(read_named(tag, :module))
        else raise UnknownTagError, "byte #{tag.unpack1('C')} at offset #{@position - 1}"
        end
      end

      def read_symbol(tag)
        node = Node.new(type: :symbol, tag: tag, value: read_counted_bytes.to_sym)
        symbols << node.value
        node
      end

      def read_symlink(tag)
        index = read_fixnum
        raise InvalidLinkError, "symlink #{index} of #{symbols.length}" unless symbols[index] && index >= 0

        Node.new(type: :symlink, tag: tag, value: symbols[index])
      end

      def read_object_link(tag)
        index = read_fixnum
        raise InvalidLinkError, "object link #{index} of #{objects.length}" unless objects[index] && index >= 0

        Node.new(type: :object_link, tag: tag, value: index)
      end

      def read_bignum(tag)
        negative = take(1) == BIGNUM_SIGN_NEGATIVE
        magnitude = little_endian(take(read_count(ROLE_BIGNUM) * BIGNUM_WORD_BYTES))
        Node.new(type: :bignum, tag: tag, value: negative ? -magnitude : magnitude)
      end

      def read_float(tag)
        Node.new(type: :float, tag: tag, value: Float(read_counted_bytes))
      rescue ArgumentError
        Node.new(type: :float, tag: tag)
      end

      def read_string(tag)
        Node.new(type: :string, tag: tag, value: read_counted_bytes)
      end

      def read_regexp(tag)
        node = Node.new(type: :regexp, tag: tag, value: read_counted_bytes)
        take(1)
        node
      end

      def read_array(tag, depth)
        node = register(Node.new(type: :array, tag: tag))
        read_count(ROLE_ARRAY).times { node.children << read_value(depth + 1) }
        node
      end

      def read_hash(tag, depth)
        node = register(Node.new(type: :hash, tag: tag))
        read_count(ROLE_HASH).times { node.children << read_pair(depth) }
        node.children << read_value(depth + 1) if tag == TAG_HASH_DEFAULT
        node
      end

      def read_pair(depth)
        pair = Node.new(type: :pair)
        pair.children << read_value(depth + 1)
        pair.children << read_value(depth + 1)
        pair
      end

      def read_ivar(tag, depth)
        inner = read_value(depth)
        read_count(ROLE_IVAR).times do
          name = read_value(depth + 1)
          inner.auxiliary << name
          inner.instance_variables_map[name.value] = read_value(depth + 1)
        end
        inner
      end

      def read_object(tag, depth)
        node = register(Node.new(type: :object, tag: tag))
        class_node = read_value(depth + 1)
        node.class_name = class_node.value.to_s
        node.auxiliary << class_node
        read_count(ROLE_IVAR).times do
          name = read_value(depth + 1)
          node.auxiliary << name
          node.instance_variables_map[name.value] = read_value(depth + 1)
        end
        node
      end

      def read_struct(tag, depth)
        node = register(Node.new(type: :struct, tag: tag))
        node.class_name = read_value(depth + 1).value.to_s
        read_count(ROLE_STRUCT).times { node.children << read_pair(depth) }
        node
      end

      def read_userdef(tag)
        node = Node.new(type: :userdef, tag: tag)
        node.class_name = read_value(1).value.to_s
        node.value = read_counted_bytes
        node
      end

      def read_usermarshal(tag, depth)
        node = register(Node.new(type: :usermarshal, tag: tag))
        node.class_name = read_value(depth + 1).value.to_s
        node.children << read_value(depth + 1)
        node
      end

      def read_wrapped(tag, type, depth)
        node = register(Node.new(type: type, tag: tag))
        node.class_name = read_value(depth + 1).value.to_s
        node.children << read_value(depth + 1)
        node
      end

      def read_named(tag, type)
        Node.new(type: type, tag: tag, class_name: read_counted_bytes)
      end
    end
  end
end
