#!/usr/bin/env perl

use strict;
use warnings;

our $VERSION = '2.10';

use sigtrap qw(die untrapped normal-signals);

use FindBin qw($Bin $Script);
use lib "$Bin/../lib";

use Log::Log4perl qw(:easy);
use Getopt::Long qw(GetOptions);
use Captive::Portal;
use Captive::Portal::TestServer;

$ENV{PATH} = '/sbin:/bin:/usr/sbin:/usr/bin';

my $cfg_file =
     $ENV{CAPTIVE_PORTAL_CONFIG}
  || -e "$Bin/../etc/local/config.pl" && "$Bin/../etc/local/config.pl"
  || -e "$Bin/../etc/config.pl" && "$Bin/../etc/config.pl";

my $log4perl =
     $ENV{CAPTIVE_PORTAL_LOG4PERL}
  || -e "$Bin/../etc/local/log4perl.conf" && "$Bin/../etc/local/log4perl.conf"
  || -e "$Bin/../etc/log4perl.conf" && "$Bin/../etc/log4perl.conf";

GetOptions(
    'loggfile=s' => \$log4perl,
    'file=s'     => \$cfg_file,
) or usage();

usage('configfile missing and CAPTIVE_PORTAL_CONFIG not set')
  unless $cfg_file;

if ( $log4perl && -f $log4perl ) {
    Log::Log4perl->init($log4perl);
}
else {
    Log::Log4perl->easy_init($DEBUG);
}

DEBUG("create new Captive::Portal object ...");
my $capo = Captive::Portal->new( cfg_file => $cfg_file );

my $port = 3333;
DEBUG("create new Captive::Portal::TestServer object ...");
my $server = Captive::Portal::TestServer->new($port);


$server->{capo}        = $capo;
$server->{static_root} = $capo->cfg->{DOCUMENT_ROOT};

INFO("You can connect the server on Port: $port");
$server->run;

sub usage {
    die "$Script [-f config_file -l log4perl.cfg]\n";
}

