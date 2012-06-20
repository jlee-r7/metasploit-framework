#
# by kernelsmith (kernelsmith+\x40+kernelsmith+\.com)
#

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/eventlog'
load 'lib/msf/core/post/windows/eventlog.rb'

class Metasploit3 < Msf::Post

	include Msf::ModuleTest::PostTest
	include Msf::Post::Windows::Eventlog

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Test EventLog',
				'Description'   => %q{
					This module will test windows EventLog methods within a meterpreter
					session.
				},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'egypt'],
				'Version'       => '$Revision: 11663 $',
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))
	end

	def run

		it "should list eventlogs" do
			eventlog_list
		end

		it "should have an 'Application' eventlog" do
			log = eventlog_list

			log.include? "Application"
		end

		it "should open the 'Application' eventlog" do
			log = eventlog_open("Application")
			log.close

			true
		end

		it "should read records from the 'Application' eventlog" do
			log = eventlog_open("Application")

			p log.read_forwards

			true
		end

	end

end
