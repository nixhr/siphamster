# siphamster
SIP traffic collector and analyzer

# Installation

1. `git clone https://github.com/nixhr/siphamster`
3. create the database and table (see createdb.sql) and required grants
2. Copy `sipcollector.pl`, `sipanalyzer.pl` and `siphamster.ini` to your preferred locations
3. Modify config file path in `sipcollector.pl`, `sipanalyzer.pl`
4. Add following iptables rules:
~~~~
-A INPUT ! -i lo -p udp -m udp --dport 5060 -j CONNMARK --set-xmark 0x6/0xffffffff
-A INPUT -p udp -m udp --dport 5060 -m connmark --mark 0x6 -j NFLOG --nflog-group 6
-A OUTPUT ! -o lo -p udp -m udp --sport 5060 -j CONNMARK --set-xmark 0x6/0xffffffff
-A OUTPUT -p udp -m udp --sport 5060 -m connmark --mark 0x6 -j NFLOG --nflog-group 6
~~~~

# Usage 

1. start `sipcollector.pl [-v]` 
2. use sipanalyzer.pl like:

~~~~
./sipanalyzer.pl options

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
~~~~
