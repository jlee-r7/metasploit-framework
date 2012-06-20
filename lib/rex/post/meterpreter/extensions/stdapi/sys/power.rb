#!/usr/bin/env ruby

require 'rex/post/process'
require 'rex/post/meterpreter/packet'
require 'rex/post/meterpreter/client'
require 'rex/post/meterpreter/extensions/stdapi/constants'
require 'rex/post/meterpreter/extensions/stdapi/stdapi'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Sys

###
#
# This class provides access to the power of the remote machine (reboot, etc).
#
###
class PowerExtension

	attr_accessor :client

	def initialize(client)
		self.client = client
	end

	#
	# Calls ExitWindows on the remote machine with the supplied parameters.
	#
	def _exitwindows(flags, reason = 0) # :nodoc:
		request = Packet.create_request('stdapi_sys_power_exitwindows')

		request.add_tlv(TLV_TYPE_POWER_FLAGS, flags);
		request.add_tlv(TLV_TYPE_POWER_REASON, reason);

		response = client.send_request(request)

		return self
	end

	#
	# Reboots the remote machine.
	#
	def reboot(reason = 0)
		self._exitwindows(EWX_REBOOT, reason)
	end

	#
	# Shuts down the remote machine.
	#
	def shutdown(force = 0, reason = 0)
		flags  = EWX_POWEROFF
		flags |= EWX_FORCEIFHUNG if force == 1
		flags |= EWX_FORCE       if force == 2

		self._exitwindows(flags, reason)
	end

end

end end end end end end
