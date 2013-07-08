require 'set'

class Rex::RandomIdentifierGenerator

	DefaultOpts = {
		# Arbitrary
		:max_length => 12,
		:min_length => 3,
		# This should be pretty universal for identifier rules
		:char_set => Rex::Text::AlphaNumeric+"_",
	}

	def initialize(opts={})
		@identifiers = Set.new
		@opts = DefaultOpts.merge(opts)
		if @opts[:min_length] < 1 || @opts[:max_length] < 1 || @opts[:max_length] < @opts[:min_length]
			raise ArgumentError, "Invalid length options"
		end
	end

	# Create a random string that satisfies most languages requirements
	# for identifiers.
	#
	# Note that the first character will always be lowercase alpha.
	#
	# @param len [Fixnum] Avoid setting this unless necessary. Default is
	#   random within range of min .. max
	# @return [String] A string that matches [a-z][a-zA-Z0-9_]*
	def generate(len=nil)
		raise ArgumentError, "len must be positive integer" if len && len < 1
		len ||= rand(@opts[:min_length] .. (@opts[:max_length]-1))
		ident = ""

		# Warning: infinite loop if we've exhausted the space. Mitigated by
		# the fact that you'd have to call generate at least 26*62 times
		# to hit it.
		loop do
			ident  = Rex::Text.rand_text_alpha_lower(1)
			ident << Rex::Text.rand_base(len-1, "", @opts[:char_set])
			# Try to make another one if it collides with a previously
			# generated one.
			break unless @identifiers.include?(ident)
		end

		ident
	end

end
