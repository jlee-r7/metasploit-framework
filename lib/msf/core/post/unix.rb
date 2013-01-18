# -*- coding: binary -*-

module Msf
class Post
module Unix

	@@passwd_locations = [
			"/etc/passwd",
			"/etc/security/passwd",  # AIX
			"/etc/master.passwd",    # BSD
	]

	#
	# Returns an array of hashes each representing a user
	# Keys are name, uid, gid, info, dir and shell
	#
	def get_users
		users = []
		etc_passwd = nil
		@@passwd_locations.each { |f|
			if file_exist?(f)
				etc_passwd = f
				break
			end
		}

		passwd_data = read_file(etc_passwd).split("\n")
		passwd_data.each do |l|
			entry = {}
			user_field = l.split(":")
			entry[:name]  = user_field[0]
			entry[:uid]   = user_field[2]
			entry[:gid]   = user_field[3]
			entry[:info]  = user_field[4]
			entry[:dir]   = user_field[5]
			entry[:shell] = user_field[6]
			users << entry
		end
		return users
	end

	#
	# Returns an array of hashes each hash representing a user group
	# Keys are name, gid and users
	#
	def get_groups
		groups = []
		cmd_out = read_file("/etc/group").split("\n")
		cmd_out.each do |l|
			entry = {}
			user_field = l.split(":")
			entry[:name] = user_field[0]
			entry[:gid] = user_field[2]
			entry[:users] = user_field[3]
			groups << entry
		end
		return groups
	end

	#
	# Enumerates the user directories in /Users or /home
	#
	def enum_user_directories
		user_dirs = []

		# get all user directories from /etc/passwd
		read_file("/etc/passwd").each_line do |passwd_line|
			user_dirs << passwd_line.split(/:/)[5]
		end

		# also list other common places for home directories in the event that
		# the users aren't in /etc/passwd (LDAP, for example)
		case session.platform
		when 'osx'
			user_dirs << cmd_exec('ls /Users').each_line.map { |l| "/Users/#{l}" }
		else
			user_dirs << cmd_exec('ls /home').each_line.map { |l| "/home/#{l}" }
		end

		user_dirs.flatten!
		user_dirs.compact!
		user_dirs.sort!
		user_dirs.uniq!

		user_dirs
	end

	#
	# Return the current user's home directory
	#
	def get_home_dir()
		case session.platform
		when 'solaris'
			user_id = cmd_exec("/usr/xpg4/bin/id -u")

			cmd = 'cat /etc/passwd | grep ":' + user_id.gsub(' ','') + ':"'
			homedir = cmd_exec(cmd).split(":")[5]
		when 'osx'
			name = cmd_exec("whoami")
			if name == 'root'
				homedir = '/'
			else
				homedir = ::File.join("/Users", name)
			end
		when  'bsd'
			cmd = %q{while IFS=":" read -r a b c d e f g
				do 
				  echo :$c:$f
				done < /etc/passwd | /usr/bin/grep ":$(id -u):"}
				homedir = cmd_exec(cmd).split(":")[2].gsub("\n", "")
		when 'linux'
			cmd = %q{while IFS=":" read -r a b c d e f g
				do 
				  echo :$c:$f
				done < /etc/passwd | /bin/grep ":$(id -u):"}
				homedir = cmd_exec(cmd).split(":")[2].gsub("\n", "")
		end
		raise "Error while requesting home dir" unless homedir =~ /^\/[A-Za-z0-9_\-\/]*$/
		return homedir
	end

	def get_arch
		arch = cmd_exec("uname -m")
		case arch
		when /x86_64/
			return "x64"
		when /(i[3-6]86)|(i86pc)/
			return "x86"
		else
			return arch
		end		
	end

end
end
end

