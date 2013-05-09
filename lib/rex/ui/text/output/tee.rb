# -*- coding: binary -*-
require 'rex/ui'

module Rex
module Ui
module Text

###
#
# This class implements output against a file and stdout
#
###
class Output::Tee < Rex::Ui::Text::Output::Stdio

	attr_accessor :fd

	def initialize(path)
		self.fd = ::File.open(path, "ab")
		super()
	end

	#
	# Prints the supplied message to file output.
	#
	def print_raw(msg = '')
		super

		return if not self.fd
		self.fd.write(msg)
		self.fd.flush
		msg
	end

	def close
		self.fd.close if self.fd
		self.fd = nil
	end
end

end
end
end

