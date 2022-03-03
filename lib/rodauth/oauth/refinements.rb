# frozen_string_literal: true

module Rodauth
  module PrefixExtensions
    unless String.method_defined?(:delete_prefix)
      refine(String) do
        def delete_suffix(suffix)
          suffix = suffix.to_s
          len = suffix.length
          return dup unless len.positive? && index(suffix, -len)

          self[0...-len]
        end

        def delete_prefix(prefix)
          prefix = prefix.to_s
          return dup unless rindex(prefix, 0)

          self[prefix.length..-1]
        end
      end
    end

    unless String.method_defined?(:delete_suffix!)
      refine(String) do
        def delete_suffix!(suffix)
          suffix = suffix.to_s
          chomp! if frozen?
          len = suffix.length
          return unless len.positive? && index(suffix, -len)

          self[-len..-1] = ""
          self
        end
      end
    end
  end

  module RegexpExtensions
    unless Regexp.method_defined?(:match?)
      refine(Regexp) do
        def match?(*args)
          !match(*args).nil?
        end
      end
    end
  end
end
