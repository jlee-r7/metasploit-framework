#!/usr/bin/env ruby

require 'rex/post/meterpreter/object_aliases'
require 'rex/post/meterpreter/extension'
require 'rex/post/meterpreter/extensions/stdapi/constants'
require 'rex/post/meterpreter/extensions/stdapi/tlv'
require 'rex/post/meterpreter/extensions/stdapi/fs/dir'
require 'rex/post/meterpreter/extensions/stdapi/fs/file'
require 'rex/post/meterpreter/extensions/stdapi/fs/file_stat'
require 'rex/post/meterpreter/extensions/stdapi/net/config'
require 'rex/post/meterpreter/extensions/stdapi/net/socket'
require 'rex/post/meterpreter/extensions/stdapi/sys/config'
require 'rex/post/meterpreter/extensions/stdapi/sys/process'
require 'rex/post/meterpreter/extensions/stdapi/sys/registry'
require 'rex/post/meterpreter/extensions/stdapi/sys/event_log'
require 'rex/post/meterpreter/extensions/stdapi/sys/power'
require 'rex/post/meterpreter/extensions/stdapi/railgun/railgun'
require 'rex/post/meterpreter/extensions/stdapi/ui'
require 'rex/post/meterpreter/extensions/stdapi/webcam/webcam'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi

###
#
# Standard ruby interface to remote entities for meterpreter.  It provides
# basic access to files, network, system, and other properties of the remote
# machine that are fairly universal.
#
###
class Stdapi < Extension

	#
	# Initializes an instance of the standard API extension.
	#
	def initialize(client)
		super(client, 'stdapi')

		# Alias the following things on the client object so that they
		# can be directly referenced
		client.register_extension_aliases(
			[
				{
					'name' => 'fs',
					'ext'  => ObjectAliases.new(
						{
							'dir'      => Fs::DirExtension.new(client),
							'file'     => Fs::FileExtension.new(client),
							'filestat' => Fs::FileStatExtension.new(client)
						})
				},
				{
					'name' => 'sys',
					'ext'  => ObjectAliases.new(
						{
							'config'   => Sys::Config.new(client),
							'process'  => Sys::ProcessExtension.new(client),
							'registry' => Sys::RegistryExtension.new(client),
							'eventlog' => Sys::EventLogExtension.new(client),
							'power'    => Sys::PowerExtension.new(client)
						})
				},
				{
					'name' => 'net',
					'ext'  => ObjectAliases.new(
						{
							'config'   => Rex::Post::Meterpreter::Extensions::Stdapi::Net::Config.new(client),
							'socket'   => Rex::Post::Meterpreter::Extensions::Stdapi::Net::Socket.new(client)
						})
				},
				{
					'name' => 'railgun',
					'ext'  => Rex::Post::Meterpreter::Extensions::Stdapi::Railgun::Railgun.new(client)
				},
				{
					'name' => 'webcam',
					'ext'  => Rex::Post::Meterpreter::Extensions::Stdapi::Webcam::Webcam.new(client)
				},
				{
					'name' => 'ui',
					'ext'  => UI.new(client)
				}

			])
	end

end

end; end; end; end; end
