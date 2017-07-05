#!/usr/bin/perl

use warnings;
#use strict;

# libs
use DBI;
use DateTime;
use Net::Pcap qw(:functions);
use NetPacket::Ethernet qw(:strip);
use NetPacket::IP;
use NetPacket::UDP;
use HTML::Entities;
use Time::HiRes qw(gettimeofday tv_interval);
use Config::Tiny;
use Getopt::Std;

my $opt_string = 'v';
getopts( "$opt_string", \%opt ) or usage();

$Config = Config::Tiny->read( '/etc/siphamster.conf', 'utf8' );

my $dbHost           = $Config->{_}->{MYSQL_HOST}              =~ s/"//rg;
my $dbName           = $Config->{_}->{MYSQL_DB}                =~ s/"//rg;
my $dbPort           = $Config->{_}->{MYSQL_PORT}              =~ s/"//rg;
my $dbUser           = $Config->{_}->{MYSQL_USER}              =~ s/"//rg;
my $dbPass           = $Config->{_}->{MYSQL_PASS}              =~ s/"//rg;
my $pcap_dev         = $Config->{_}->{PCAP_DEV}              =~ s/"//rg;

########################
# connect to database
$dbh = DBI->connect("DBI:mysql:database=$dbName;host=$dbHost",
                         "$dbUser", "$dbPass",
             {'RaiseError' => 1,
              'PrintError' => 1,
              'mysql_auto_reconnect'=>1}) ||fatal_error("*** Database error: $DBI::errstr");

my $sth_addpacket = $dbh->prepare(
  "INSERT INTO sip_log(timeGMT, timeMicroSec, srcAddress, srcPort, " .
  "dstAddress, dstPort, sipID, sipCSeq, sipFrom, sipTo, sipUserAgent, sipCommand, sipData) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)");

# init network
my $err;
my $pcap = pcap_open_live($pcap_dev, 10240, 0, 0, \$err)
  or die "Can't open device $pcap_dev: $err";

# stats reporting
my $stored = 0;
my $last_stats = time;

# report data link
my $datalink = pcap_datalink_val_to_name(pcap_datalink($pcap));
$| = 1; # disable output buffering (for runit logging)
print "Capturing device '$pcap_dev' using datalink $datalink\n";

# drop root privileges
my $nobody = getpwnam('nobody');
my $nogroup = getgrnam('nogroup');
$) = "$nogroup $nogroup";
$( = $nogroup;
$< = $> = $nobody;

# collect the packets
my $ret = pcap_loop($pcap, 0, \&process_packet, 'sip');
$err = pcap_geterr($pcap);
print "Failure in pcap_loop: $ret $err\n";

# close network
pcap_close($pcap);

# close database
$dbh->disconnect();


sub process_packet {
  my ($user_data, $header, $packet) = @_;
  my ($rx, $ip, $udp);

  my $t0 = [gettimeofday];
  my $time = DateTime->from_epoch(epoch => "$header->{tv_sec}.$header->{tv_usec}");
  $time->set_time_zone( 'Europe/Zagreb' );

  my ($af, $ver, $res) = unpack("CCn", $packet);
  print "Got packet af=$af ver=$ver res=$res\n" if $opt{v};

  # decode network info
  my $pos = 4;
  my $size = length($packet);
  while ($pos < $size) {
    my ($len, $type) = unpack("SS", substr($packet, $pos, 4));
    #print "TLV t=$type l=$len\n" if $opt{v};

    if ($type == 9) {
      $ip = NetPacket::IP->decode(substr($packet, $pos + 4, $len - 4));
      $udp = NetPacket::UDP->decode($ip->{data});
    }

    if ($type == 4 or $type == 6) {
      $rx = 1;
    }

    $pos += $len;
    if ($pos % 4) { # align to 4 bytes
      $pos += 4 - $pos % 4;
    }
  }

  # decode sip info
  my @sip_headers = split("\r\n", $udp->{data});
  my $sip_command = shift @sip_headers;
  my %header;
  for my $header (@sip_headers) {
    last if $header eq "";
    my ($attr, $val) = $header =~ m/^([^ ]+): (.*)/;
    $header{$attr} = $val;
  }

  # report stats every minute
  if (time - $last_stats > 60) {
    my %stats;

    $last_stats = time;
    pcap_stats($pcap, \%stats);
    printf "RECV=%d STORED=%d DROP=%d IFDROP=%d\n",
      $stats{ps_recv}, $stored, $stats{ps_drop}, $stats{ps_ifdrop};
  }

  # load call ids
  my $sip_call = $header{'Call-ID'};
  my $sip_cseq = $header{'CSeq'};
  my $sip_from = $header{'From'};
  my $sip_to = $header{'To'};
  my $sip_useragent = $header{'User-Agent'};
  return unless $sip_call;

  # store packet to sip_log
  $sth_addpacket->execute(
    "$time->ymd $time->hms", $time->microsecond, $ip->{src_ip}, $udp->{src_port},
    $ip->{dest_ip}, $udp->{dest_port}, $sip_call, $sip_cseq, $sip_from, $sip_to, $sip_useragent, $sip_command, $udp->{data}
  );

  # update stats
  $stored++;

  printf("%-18s -> %-18s : %-40s processed in %f sec\n",
    $ip->{src_ip}, $ip->{dest_ip}, $sip_command, tv_interval($t0)) if $opt{v};
}
