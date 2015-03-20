##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Capture
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'TCP SYN Port Scanner',
      'Description' => %q{
        Enumerate open TCP services using a raw SYN scan.
      },
      'Author'      => 'kris katterjohn',
      'License'     => MSF_LICENSE
    )

    register_options([
      OptString.new('PORTS', [true, "Ports to scan (e.g. 22-25,80,110-900)", "1-10000"]),
      OptInt.new('TIMEOUT', [true, "The reply read timeout in milliseconds", 500]),
      OptInt.new('BATCHSIZE', [true, "The number of hosts to scan per set", 256]),
      OptString.new('INTERFACE', [false, 'The name of the interface'])
    ], self.class)

    deregister_options('FILTER','PCAPFILE')
  end

  # No IPv6 support yet
  def support_ipv6?
    false
  end

  def run_batch_size
    datastore['BATCHSIZE'] || 256
  end

  def run_batch(hosts)
    open_pcap

    ports = Rex::Socket.portspec_crack(datastore['PORTS'])

    if ports.empty?
      raise Msf::OptionValidateError.new(['PORTS'])
    end

    seen = {}
    # Spread the load across the hosts
    ports.each do |dport|
      hosts.each do |dhost|
        shost, sport = getsource(dhost)

        self.capture.setfilter(getfilter(shost, sport, dhost, dport))

        begin
          probe = buildprobe(shost, sport, dhost, dport)

          capture_sendto(probe, dhost)

          reply = wait_for_next_packet(:tcp)

          next if not reply

          if !seen[dhost] && should_arp?(dhost)
            # This box is in our local subnet, record its hardware address
            report_host(host: dhost, mac: reply.eth_saddr)
            seen[dhost] = true
          end

          if (reply.is_tcp? and reply.tcp_flags.syn == 1 and reply.tcp_flags.ack == 1)
            print_status(" TCP OPEN #{dhost}:#{dport}")
            report_service(:host => dhost, :port => dport)
          end
        rescue ::Exception
          # Gotta catch 'em all!
          print_error("Error: #{$!.class} #{$!}")
          print_debug($!.backtrace.join("\n"))
        end
      end
    end

    close_pcap
  end

  def getfilter(shost, sport, dhost, dport)
    # Look for associated SYN/ACKs and RSTs
    "tcp and (tcp[13] == 0x12 or (tcp[13] & 0x04) != 0) and " +
    "src host #{dhost} and src port #{dport} and " +
    "dst host #{shost} and dst port #{sport}"
  end

  def getsource(dhost)
    # srcip, srcport
    [ Rex::Socket.source_address(dhost), rand(0xffff - 1025) + 1025 ]
  end

  def buildprobe(shost, sport, dhost, dport)
    p = PacketFu::TCPPacket.new
    p.ip_saddr = shost
    p.ip_daddr = dhost
    p.tcp_sport = sport
    p.tcp_flags.ack = 0
    p.tcp_flags.syn = 1
    p.tcp_dport = dport
    p.tcp_win = 3072
    p.recalc
    p
  end

end
