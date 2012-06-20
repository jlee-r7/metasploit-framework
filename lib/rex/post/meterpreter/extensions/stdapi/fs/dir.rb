#!/usr/bin/env ruby

require 'rex/post/dir'
require 'rex/post/meterpreter/extensions/stdapi/stdapi'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Fs

class DirExtension
	attr_accessor :client

	def initialize(client)
		self.client = client
	end

	#
	# Enumerates all of the files/folders in a given directory.
	#
	def entries(name = getwd)
		request = Packet.create_request('stdapi_fs_ls')
		files   = []

		request.add_tlv(TLV_TYPE_DIRECTORY_PATH, client.unicode_filter_decode(name))

		response = client.send_request(request)

		response.each(TLV_TYPE_FILE_NAME) { |file_name|
			files << client.unicode_filter_encode( file_name.value )
		}

		return files
	end

	#
	# Enumerates files with a bit more information than the default entries.
	#
	def entries_with_info(name = getwd)
		request = Packet.create_request('stdapi_fs_ls')
		files   = []

		request.add_tlv(TLV_TYPE_DIRECTORY_PATH, client.unicode_filter_decode(name))

		response = client.send_request(request)

		fname = response.get_tlvs(TLV_TYPE_FILE_NAME)
		fpath = response.get_tlvs(TLV_TYPE_FILE_PATH)
		sbuf  = response.get_tlvs(TLV_TYPE_STAT_BUF)

		if (!fname or !sbuf)
			return []
		end

		fname.each_with_index { |file_name, idx|
			st = nil

			if (sbuf[idx])
				st = ::Rex::Post::FileStat.new
				st.update(sbuf[idx].value)
			end

			files <<
				{
					'FileName' => client.unicode_filter_encode( file_name.value ),
					'FilePath' => client.unicode_filter_encode( fpath[idx].value ),
					'StatBuf'  => st,
				}
		}

		return files
	end

	##
	#
	# General directory operations
	#
	##

	#
	# Changes the working directory of the remote process.
	#
	def chdir(path)
		request = Packet.create_request('stdapi_fs_chdir')

		request.add_tlv(TLV_TYPE_DIRECTORY_PATH, client.unicode_filter_decode( path ))

		response = client.send_request(request)

		return 0
	end

	#
	# Creates a directory.
	#
	def mkdir(path)
		request = Packet.create_request('stdapi_fs_mkdir')

		request.add_tlv(TLV_TYPE_DIRECTORY_PATH, client.unicode_filter_decode( path ))

		response = client.send_request(request)

		return 0
	end

	#
	# Returns the current working directory of the remote process.
	#
	def pwd
		request = Packet.create_request('stdapi_fs_getwd')

		response = client.send_request(request)

		return client.unicode_filter_encode( response.get_tlv(TLV_TYPE_DIRECTORY_PATH).value )
	end

	#
	# Synonym for pwd.
	#
	def getwd
		pwd
	end

	#
	# Removes the supplied directory if it's empty.
	#
	def delete(path)
		request = Packet.create_request('stdapi_fs_delete_dir')

		request.add_tlv(TLV_TYPE_DIRECTORY_PATH, client.unicode_filter_decode( path ))

		response = client.send_request(request)

		return 0
	end

	#
	# Synonyms for delete.
	#
	def rmdir(path)
		delete(path)
	end

	#
	# Synonyms for delete.
	#
	def unlink(path)
		delete(path)
	end

	##
	#
	# Directory mirroring
	#
	##

	#
	# Downloads the contents of a remote directory a
	# local directory, optionally in a recursive fashion.
	#
	def download(dst, src, recursive = false, force = true, &stat)

		self.entries(src).each { |src_sub|
			dst_item = dst + ::File::SEPARATOR + client.unicode_filter_encode( src_sub )
			src_item = src + client.fs.file.separator + client.unicode_filter_encode( src_sub )

			if (src_sub == '.' or src_sub == '..')
				next
			end

			src_stat = client.fs.filestat.new(src_item)

			if (src_stat.file?)
				stat.call('downloading', src_item, dst_item) if (stat)
				begin
					client.fs.file.download(dst_item, src_item)
					stat.call('downloaded', src_item, dst_item) if (stat)
				rescue ::Rex::Post::Meterpreter::RequestError => e
					if force
						stat.call('failed', src_item, dst_item) if (stat)
					else
						raise e
					end
				end

			elsif (src_stat.directory?)
				if (recursive == false)
					next
				end

				begin
					::Dir.mkdir(dst_item)
				rescue
				end

				stat.call('mirroring', src_item, dst_item) if (stat)
				download(dst_item, src_item, recursive, force, &stat)
				stat.call('mirrored', src_item, dst_item) if (stat)
			end
		}
	end

	#
	# Uploads the contents of a local directory to a remote
	# directory, optionally in a recursive fashion.
	#
	def upload(dst, src, recursive = false, &stat)
		::Dir.entries(src).each { |src_sub|
			dst_item = dst + client.fs.file.separator + client.unicode_filter_encode( src_sub )
			src_item = src + ::File::SEPARATOR + client.unicode_filter_encode( src_sub )

			if (src_sub == '.' or src_sub == '..')
				next
			end

			src_stat = ::File.stat(src_item)

			if (src_stat.file?)
				stat.call('uploading', src_item, dst_item) if (stat)
				client.fs.file.upload(dst_item, src_item)
				stat.call('uploaded', src_item, dst_item) if (stat)
			elsif (src_stat.directory?)
				if (recursive == false)
					next
				end

				begin
					self.mkdir(dst_item)
				rescue
				end

				stat.call('mirroring', src_item, dst_item) if (stat)
				upload(dst_item, src_item, recursive, &stat)
				stat.call('mirrored', src_item, dst_item) if (stat)
			end
		}
	end

	#
	# Factory method for creating a File object
	#
	def new(*args)
		Dir.new(client, *args)
	end


end


###
#
# This class implements directory operations against the remote endpoint.  It
# implements the Rex::Post::Dir interface.
#
###
class Dir < Rex::Post::Dir

	attr_accessor :client

	##
	#
	# Constructor
	#
	##

	#
	# Initializes the directory instance.
	#
	def initialize(client, path)
		self.client = client
		self.path   = path
	end

	##
	#
	# Enumeration
	#
	##

	#
	# Enumerates all of the contents of the directory.
	#
	def each(&block)
		client.fs.dir.foreach(self.path, &block)
	end


	#
	# The path of the directory that was opened.
	#
	attr_reader   :path
protected
	attr_accessor :client # :nodoc:
	attr_writer   :path # :nodoc:

end

end; end; end; end; end; end

