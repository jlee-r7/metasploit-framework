require 'spec_helper'
require 'msf/core/post/unix'

describe Msf::Post::Unix do
	let :passwd_data do
		%Q|bin:x:1:1:bin:/bin:/bin/false\n| +
		%Q|postgres:x:70:71:added by portage for postgresql-server:/var/lib/postgresql:/bin/bash\n|
	end
	let :group_data do
		%Q|root:x:0:root\n| +
		%Q|bin:x:1:root,bin,daemon\n| +
		%Q|daemon:x:2:root,bin,daemon\n|
	end
	subject do
		klass = Class.new { include Msf::Post::Unix; attr_accessor :session }
		s = klass.new
		s.session = mock("session")
		s.stub(:read_file) do |fname|
			case fname
			when "/etc/group"
				group_data
			when "/etc/passwd", "/etc/master.passwd", "/etc/security/passwd"
				passwd_data
			else
				""
			end
		end

		s
	end

	describe "#get_users" do
		context "with /etc/passwd" do
			it "should parse simple /etc/passwd" do
				subject.should_receive(:file_exist?).with("/etc/passwd").and_return(true)

				users = subject.get_users
				users.should be_a(Array)
				users.length.should == 2

				bin = users.first
				bin[:uid].should == "1"
				bin[:info].should == "bin"

				pg = users.last
				pg[:uid].should == "70"
				pg[:gid].should == "71"
				pg[:dir].should == "/var/lib/postgresql"
				pg[:shell].should == "/bin/bash"
			end
		end
		context "with non-existent /etc/passwd" do
			it "should return an empty array" do
				subject.should_receive(:file_exist?).at_least(1).times.and_return(false)
				subject.get_users.should be_empty
			end
		end
	end

	describe "#get_groups" do
		it "should parse simple /etc/group" do
			#subject.should_receive(:file_exist?).at_least(1).times.with("/etc/group").and_return(true)

			groups = subject.get_groups
			groups.should be_a(Array)
			groups.length.should == 3
		end
	end

end

