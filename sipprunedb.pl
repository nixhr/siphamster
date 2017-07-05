#!/usr/bin/perl

#use warnings;
#use strict;

# libs
use DBI;
use DateTime;
use Config::Tiny;
use Getopt::Std;

$Config = Config::Tiny->read( '/etc/siphamster.conf', 'utf8' );

my $dbHost           = $Config->{_}->{MYSQL_HOST}              =~ s/"//rg;
my $dbName           = $Config->{_}->{MYSQL_DB}                =~ s/"//rg;
my $dbPort           = $Config->{_}->{MYSQL_PORT}              =~ s/"//rg;
my $dbUser           = $Config->{_}->{MYSQL_USER}              =~ s/"//rg;
my $dbPass           = $Config->{_}->{MYSQL_PASS}              =~ s/"//rg;

########################
# connect to database
$dbh = DBI->connect("DBI:mysql:database=$dbName;host=$dbHost",
                         "$dbUser", "$dbPass",
             {'RaiseError' => 0,
              'PrintError' => 0}) ||fatal_error("*** Database error: $DBI::errstr");

# h - delete records where time = NOW() - $opt{h} hours (default 24)
# s - print sql commands

my $opt_string = 'h:s';
getopts( "$opt_string", \%opt ) or usage();
$sql_debug = 1 if $opt{s};
$hours=$opt{h} || 24;

$sql = "DELETE FROM sip_log WHERE timeGMT < (NOW() - INTERVAL $hours HOUR)";
print "$sql\n" if $sql_debug;
$dbh->do($sql) || fatal_error("*** Database error: $DBI::errstr");


sub usage {
    print STDERR << "EOF";

usage: $0 options

OPTIONS:
    -h <hours>   delete records older than opt_h hours
    -s           show sql commands
EOF
    exit 0;
}

sub fatal_error {
  my $string = shift;
  print STDERR "$string\n";
}
