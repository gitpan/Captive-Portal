#!/usr/bin/env perl

use strict;
use warnings;

our $VERSION = '2.10';

use sigtrap qw(die untrapped normal-signals);

use FindBin qw($Bin $Script);
use lib "$Bin/../lib";

use CGI;
use WWW::Mechanize::CGI;
use Log::Log4perl qw(:easy);
use Getopt::Long qw(GetOptions);
use Captive::Portal;

$ENV{PATH} = '/sbin:/bin:/usr/sbin:/usr/bin';

$0 = $Script;

my $cfg_file =
     $ENV{CAPTIVE_PORTAL_CONFIG}
  || -e "$Bin/../etc/local/config.pl" && "$Bin/../etc/local/config.pl"
  || -e "$Bin/../etc/config.pl" && "$Bin/../etc/config.pl";

my $log4perl = $ENV{CAPTIVE_PORTAL_LOG4PERL}
  || -e "$Bin/../etc/local/log4perl.conf"
  && "$Bin/../etc/local/log4perl.conf"
  || -e "$Bin/../etc/log4perl.conf" && "$Bin/../etc/log4perl.conf";

GetOptions(
    'loggfile=s' => \$log4perl,
    'file=s'     => \$cfg_file,
) or usage();

if ( $log4perl && -f $log4perl ) {
    Log::Log4perl->init($log4perl);
}
else {
    Log::Log4perl->easy_init($DEBUG);
}

my $url = shift;
usage('url missing')   unless $url;

DEBUG "create new Captive Portal object";
my $capo = Captive::Portal->new( cfg_file => $cfg_file );

my $mech = WWW::Mechanize::CGI->new;
$mech->cgi( sub { $capo->run( CGI->new ); } );
$mech->get($url);
print $mech->response->headers->as_string;
print "\n";
print $mech->content;

exit;

sub usage {
    warn "@_\n\n";

    die <<"EO_USAGE";
$0 [-f config_file] [-l logfile] url

Example URL's:

  'http://localhost'

  'http://localhost?login=1;username=foo;password=bar'
  'http://localhost?logout=1'

  'http://localhost?status=1'
  'http://localhost?status=1;admin_secret=my-secret'

EO_USAGE
}

