#!/usr/bin/perl

#use warnings;
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
use Term::ANSIColor;
use Config::Tiny;

$Config = Config::Tiny->read( './siphamster.conf', 'utf8' );

my $dbHost           = $Config->{_}->{MYSQL_HOST}              =~ s/"//rg;
my $dbName           = $Config->{_}->{MYSQL_DB}                =~ s/"//rg;
my $dbPort           = $Config->{_}->{MYSQL_PORT}              =~ s/"//rg;
my $dbUser           = $Config->{_}->{MYSQL_USER}              =~ s/"//rg;
my $dbPass           = $Config->{_}->{MYSQL_PASS}              =~ s/"//rg;
my $myIP             = $Config->{_}->{MY_IP_ADDRESS}           =~ s/"//rg;

########################
# connect to database
$dbh = DBI->connect("DBI:mysql:database=$dbName;host=$dbHost",
                         "$dbUser", "$dbPass",
             {'RaiseError' => 0,
              'PrintError' => 0}) ||fatal_error("*** Database error: $DBI::errstr");

# n - number
# v - verbose sip dump
# t - filter by approxmate time
# i - show only inbound legs
# m - mono, don't colorize output
# p - show precise time (including microseconds)
# f - show full SIP URI parameters
# a - filter by ip address (not implemented yet)
# r - find by user or peer
# s - print all sql statements for debugging

my $opt_string = 'n:vt:mipfa:r';
getopts( "$opt_string", \%opt ) or usage();

$number = $opt{n} if $opt{n};
$approxTime = $opt{t} if $opt{t};

$sql_debug = 1 if $opt{s};


if ($opt{r}) {
  analyze_users();
} else {
  analyze_calls("all");
}
  
sub analyze_users {
  # find registered users
  $sql = "SELECT id, timeGMT, sipFrom, srcAddress, sipCommand FROM sip_log ";
  $sql .= "WHERE " if $approxTime;
  $sql .= "timeGMT LIKE '%$approxTime%' " if $approxTime;
  $sql .= "AND " if $approxTime;
  $sql .= "WHERE " if ! $approxTime;
  $sql .= "sipCommand like 'REGISTER%' ";
  print "$sql\n" if $sql_debug; 

  $sth = $dbh->prepare("$sql")|| fatal_error("*** Database error: $DBI::errstr") ;
  $sth->execute()|| fatal_error("*** Database error: $DBI::errstr") ;
  
  while( ($id, $timeGMT, $sipFrom, $srcAddress, $sipCommand) = $sth->fetchrow_array() ) {
    if ($sipCommand =~ /^REGISTER/) {
      ($foundUserID) = $sipFrom  =~ /sip:(.*)@/;
      if ( ! grep( /^$foundUserID$/, @foundUsersID) ) {
        push (@foundUsersIP, $srcAddress);
        push (@foundUsersID, $foundUserID);
        push (@foundUsersType, "user");
       }
    }
  }
  $sth->finish;
  
  # find peers with no registration
  $sql = "SELECT id, timeGMT, sipFrom, srcAddress, sipCommand FROM sip_log WHERE srcAddress != '$myIP' AND sipCommand like 'INVITE%' "; print "$sql\n" if $sql_debug;
  $sql .= "AND timeGMT LIKE '%$approxTime%' " if $approxTime;
  print "$sql\n" if $sql_debug; 
  $sth = $dbh->prepare("$sql")|| fatal_error("*** Database error: $DBI::errstr") ;
  $sth->execute()|| fatal_error("*** Database error: $DBI::errstr") ;
 
  $count=0;
  while( ($id, $timeGMT, $sipFrom, $srcAddress, $sipCommand) = $sth->fetchrow_array() ) {
    if ($sipCommand =~ /^INVITE/) {
      $foundUserID = "peer_$count";
      if ( ! grep( /^$srcAddress$/, @foundUsersIP) ) {
        push (@foundUsersIP, $srcAddress);
        push (@foundUsersID, $foundUserID);
        push (@foundUsersType, "peer");
        $count++;
       }
    }
  }
  $sth->finish;

  foreach my $index (0..$#foundUsersID) {
    printf ("%-5s  %-25s %-18s %-10s\n", $index, $foundUsersID[$index], $foundUsersIP[$index], $foundUsersType[$index]);
  }

  print "Enter ID? ";
  $chosenID = <STDIN>;
  chomp $chosenID;
  print "whole (T)raffic or (C)alls? ";
  $trafCalls = <STDIN>;
  chomp $trafCalls;
  if ( $trafCalls =~ /^c$/i ) {
    analyze_calls("user");
  } else {
    print_user_traffic();
  }
  print "Filter per sipID? (enter sipID):  ";
  $chosenSipID = <STDIN>;
  chomp $chosenSipID;
  print_user_traffic() if ( $chosenSipID !~ /^$/ );
  
}

sub print_user_traffic {
  $sql="SELECT id, timeGMT, srcAddress, dstAddress, sipID, sipFrom, sipTo, sipUserAgent, sipCSeq, sipCommand, sipData FROM sip_log WHERE sipData LIKE '%sip:$foundUsersID[$chosenID]%' " if ($foundUsersID[$chosenID] !~ /^peer_/);
  $sql="SELECT id, timeGMT, srcAddress, dstAddress, sipID, sipFrom, sipTo, sipUserAgent, sipCSeq, sipCommand, sipData FROM sip_log WHERE (srcAddress = '$foundUsersIP[$chosenID]' OR dstAddress = '$foundUsersIP[$chosenID]')  " if ($foundUsersID[$chosenID] =~ /^peer_/);
  $sql .= "AND sipID = '$chosenSipID' " if ($chosenSipID !~ /^$/ );
  print "$sql\n" if $sql_debug; 

  $sth = $dbh->prepare("$sql")|| fatal_error("*** Database error: $DBI::errstr") ;
  $sth->execute()|| fatal_error("*** Database error: $DBI::errstr") ;
  while( ($id, $timeGMT, $srcAddress, $dstAddress, $sipID, $sipFrom, $sipTo, $sipUserAgent, $sipCSeq, $sipCommand, $sipData) = $sth->fetchrow_array() ) {
    $sipCommand =~ s/;.* / / if ! $opt{f};
  #  printf ("%-25s %-44s %-20s %20s\n", "Time", $foundUsersIP[$chosenID], $myIP, "CSeq") if ($pageLine == 0);
    if ( $srcAddress =~ /^$foundUsersIP[$chosenID]$/ ) {
     printf colored ("%-25s %-18s %-64s %-18s %-20s %-64s\n", "green"), $timeGMT, $srcAddress, "$sipCommand  ---->", "   $dstAddress", "CSeq:$sipCSeq", $sipID; 
#    printf ("%-25s %-18s %5s %-18s  %-64s\n", $timeGMT , $srcAddress, " -> ", $dstAddress,  $sipCommand);
    } else {
     printf colored ("%-25s %-18s %64s %-18s %-20s %-64s\n", "magenta"), $timeGMT, $dstAddress, "  <---- $sipCommand", "   $srcAddress", "CSeq:$sipCSeq", $sipID; 
    }
  }
  $sth->finish;
}

sub analyze_calls {
  # type = user | all
  $type = shift;
  $sql="SELECT id, timeGMT, srcAddress, dstAddress, sipID, sipFrom, sipTo, sipUserAgent, sipCSeq, sipCommand, sipData FROM sip_log ";
  $sql .= "WHERE " if ($number || $approxTime || $opt{i} || $opt{a} || ($type =~ /^user$/));
  $sql .= "sipData LIKE '%$number%' " if $number;
  $sql .= "AND " if ($number && $approxTime);
  $sql .= "timeGMT LIKE '%$approxTime%' " if $approxTime;
  $sql .= "AND " if (($number || $approxTime) && $opt{i});
  $sql .= "srcAddress != '$myIP' " if $opt{i};
  $sql .= "AND " if (($number || $approxTime || $opt{i}) && $opt{a});
  $sql .= "(srcAddress = '$opt{a}' OR dstAddress = '$opt{a}') " if $opt{a};
  $sql .= "sipData LIKE '%sip:$foundUsersID[$chosenID]%'" if ($type =~ /^user$/);
  $sql .= "group by sipID ORDER BY id ";
  print "$sql\n" if $sql_debug; 

  $sth = $dbh->prepare("$sql")|| fatal_error("*** Database error: $DBI::errstr") ;
  $sth->execute()|| fatal_error("*** Database error: $DBI::errstr") ;

  $count=0;
  while( ($id, $timeGMT, $srcAddress, $dstAddress, $sipID, $sipFrom, $sipTo, $sipUserAgent, $sipCSeq, $sipCommand, $sipData) = $sth->fetchrow_array() ) {
    if ($sipCommand =~ /^INVITE/) {
      ($srcNumber) = $sipFrom  =~ /sip:(.*)@/;
      ($dstNumber) = $sipCommand =~ m/^INVITE sip:(.*)@/;
      push (@foundCallsID, $id);
      printf ("%-5s  %-25s %-18s %5s %-18s  %-15s %5s %-15s\n", $count, $timeGMT , $srcAddress, " -> ", $dstAddress,  $srcNumber, " -> ", $dstNumber);
      $count++;
    }
  }
  $sth->finish;

  print "Enter comma separated IDs? ";
  $chosenID = <STDIN>;
  chomp $chosenID;

  if ( $choesenID !~ /,/) {
    $sql = "SELECT timeGMT,sipFrom FROM sip_log WHERE id = '$foundCallsID[$chosenID]'";
    print "$sql\n" if $sql_debug; 
    $row = $dbh->selectrow_hashref($sql) || fatal_error("*** Database error: $DBI::errstr");
    $timeGMToriginal = $row->{'timeGMT'};
    ($srcNumberOriginal) = $row->{sipFrom}  =~ /sip:(.*)@/;
    @releatedIds = ();
    print "call id: $foundCallsID[$chosenID]\n";
    $sql="SELECT id, timeGMT, srcAddress, dstAddress, sipID, sipFrom, sipTo, sipUserAgent, sipCSeq, sipCommand, sipData FROM sip_log where id != $foundCallsID[$chosenID] AND sipCommand LIKE '%INVITE%' AND sipData LIKE '%$srcNumberOriginal%' AND timeGMT < ('$timeGMToriginal' + INTERVAL 2 MINUTE) AND (timeGMT > '$timeGMToriginal' - INTERVAL 2 MINUTE) group by sipID ORDER BY id ";
    print "$sql\n" if $sql_debug; 
    $sth = $dbh->prepare("$sql")|| fatal_error("*** Database error: $DBI::errstr") ;
    $sth->execute()|| fatal_error("*** Database error: $DBI::errstr") ;
    $releatedFound = 0;
    while( ($id, $timeGMT, $srcAddress, $dstAddress, $sipID, $sipFrom, $sipTo, $sipUserAgent, $sipCSeq, $sipCommand, $sipData) = $sth->fetchrow_array() ) {
      print "Possible releated calls found:\n\n" if ($releatedFound == 0);
      $releatedFound++;
      ($srcNumber) = $sipFrom  =~ /sip:(.*)@/;
      ($dstNumber) = $sipCommand =~ m/^INVITE sip:(.*)@/;
      printf ("%-5s  %-25s %-18s %5s %-18s  %-15s %5s %-15s\n", $id, $timeGMT , $srcAddress, " -> ", $dstAddress,  $srcNumber, " -> ", $dstNumber);
      push @releatedIds, $id;
    }
    $sth->finish;
    $chosenList[0] = $foundCallsID[$chosenID];
    if ($releatedFound > 0) {
      print "show traces of releated calls (Y/n)? ";
      $showReleated = <STDIN>;
      chomp $showReleated;
      print "releated ids: @releatedIds\n";
      push (@chosenList, @releatedIds) if ($showReleated =~ /^$/ || $showReleated =~ /^Y$/i);
    }
  }

  print "chosenList: @chosenList\n";

  @chosenList = split(',',$chosenID) if ( $choesenID =~ /,/);
  @colors = ("green", "red", "yellow", "magenta", "cyan", "white", "blue");
  $colorID=0;

  $idList = join( ',', @chosenList );

  $sql="SELECT id, timeGMT, srcAddress, dstAddress, sipID, sipFrom, sipTo, sipUserAgent, sipCSeq, sipCommand, sipData FROM sip_log where id in ($idList)";
  print "$sql\n" if $sql_debug; 
  $sth = $dbh->prepare("$sql")|| fatal_error("*** Database error: $DBI::errstr") ;
  $sth->execute()|| fatal_error("*** Database error: $DBI::errstr") ;
  $count = 0;
  while(( $id, $timeGMT, $srcAddress, $dstAddress, $sipID, $sipFrom, $sipTo, $sipUserAgent, $sipCSeq, $sipCommand, $sipData) = $sth->fetchrow_array() ) {
    $startTime[$count]    = $timeGMT;
    $srcIP[$count]        = $srcAddress;
    $color{$sipID}        = $colors[$colorID];
    ($srcNum{$sipID})       = $sipFrom  =~ /sip:(.*)@/;
    ($dstNum{$sipID})       = $sipCommand =~ m/^INVITE sip:(.*)@/;
    $targetSipID[$count]  = "'$sipID'";
    ($srcNumber[$count])  = $sipFrom  =~ /sip:(.*)@/;
    ($dstNumber[$count])  = $sipCommand =~ m/^INVITE sip:(.*)@/;
    $count=$count + 1;
    $colorID = $colorID + 1;
  }

  $sipIdList = join( ',', @targetSipID );

  printf "\n Showing SIP message trace for call from $srcNumber[0] -> $dstNumber[0] initiated at $startTime[0] from IP $srcIP[0]\n\n";

  print_output();

  print "Filter per sipID? (enter sipID):  ";
  $chosenSipID = <STDIN>;
  chomp $chosenSipID;
  if ( $chosenSipID !~ /^$/ ) {
    $sipIdList = "'$chosenSipID'";
    print_output();
  }
}

sub print_output { 
  $sql="SELECT id, timeGMT, timeMicroSec, srcAddress, dstAddress, sipID, sipFrom, sipTo, sipUserAgent, sipCSeq, sipCommand, sipData FROM sip_log where sipID in ($sipIdList) ORDER BY id";
  print "$sql\n" if $sql_debug; 
  $sth = $dbh->prepare("$sql")|| fatal_error("*** Database error: $DBI::errstr") ;
  $sth->execute()|| fatal_error("*** Database error: $DBI::errstr") ;
  while( ($id, $timeGMT, $timeMicroSec, $srcAddress, $dstAddress, $sipID, $sipFrom, $sipTo, $sipUserAgent, $sipCSeq, $sipCommand, $sipData) = $sth->fetchrow_array() ) {
    $sipCommand =~ s/;.* / / if ! $opt{f};
    if ( $opt{p} ) {
      if ( ! $opt{m} ){
        printf colored ("%-31s %-15s %4s %-18s %-15s %5s %-15s %-12s %-64.64s %-64s\n", "$color{$sipID}"), "$timeGMT.$timeMicroSec" ,  $srcAddress, " -> ", $dstAddress,  $srcNum{$sipID}, " -> ", $dstNum{$sipID} ,$sipCSeq, $sipCommand, $sipID;
      } else {
        printf ("%-31s %-15s %4s %-18s %-15s %5s %-15s %-12s %-64.64s %-64s\n", "$timeGMT.$timeMicroSec" ,  $srcAddress, " -> ", $dstAddress, $srcNum{$sipID}, " -> ", $dstNum{$sipID}, $sipCSeq, $sipCommand, $sipID);
      } 
    } else {
      if ( ! $opt{m} ){
        printf colored ("%-25s %-15s %4s %-18s %-15s %5s %-15s %-12s %-64.64s %-64s\n", "$color{$sipID}"), $timeGMT ,  $srcAddress, " -> ", $dstAddress,  $srcNum{$sipID}, " -> ", $dstNum{$sipID} ,$sipCSeq, $sipCommand, $sipID;
      } else {
        printf ("%-25s %-15s %4s %-18s %-15s %5s %-15s %-12s %-64.64s %-64s\n", $timeGMT ,  $srcAddress, " -> ", $dstAddress, $srcNum{$sipID}, " -> ", $dstNum{$sipID}, $sipCSeq, $sipCommand, $sipID);
      } 
    }
  }
  $sth->finish;
}

sub usage {
    print STDERR << "EOF";

usage: $0 options

OPTIONS:
   -i      show only inbound call legs
   -n      find calls by source or destination number
   -r      find calls/traffic by user or peer
   -v      verbose sip dump (not implemented yet)
   -t      approximate time of call
   -m      mono, don't colorize output
   -p      show precise time (including microseconds)
   -f      show full SIP URI parameters
   -a      filter by ip address (not implemented yet)
   -s      print all sql statements for debugging
EOF
    exit 0;
}

sub fatal_error {
  my $string = shift;
  print STDERR "$string\n";
}
