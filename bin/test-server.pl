#!/usr/bin/env perl

use strict;
use warnings;

our $VERSION = '2.18';

=head1 NAME

test-server.pl - single threaded HTTP/CGI testserver

=head1 DESCRIPTION

Don't use it in production, SSL/TLS and FCGI not supported.

=head1 SYNOPSIS

 test-server.pl [-p -port ] [- f capo.cfg] [-l log4perl.cfg]

=head1 OPTIONS

=over 4

=item B<--port> 3333

HTTP listen port. If not defined listens on port 3333

=item B<--file> capo.cfg

Captive::Portal config file. If not defined looks for the following files

    $ENV{CAPTIVE_PORTAL_CONFIG} ||
    $Bin/../etc/local/config.pl ||
    $Bin/../etc/config.pl

=item B<--logg> log4perl.cfg

Log::Log4perl config file. If not defined looks for the following files

    $ENV{CAPTIVE_PORTAL_LOG4PERL}   ||
    $Bin/../etc/local/log4perl.conf ||
    $Bin/../etc/log4perl.conf

=back

=cut

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

my $port = 3333;

GetOptions(
    'loggfile=s' => \$log4perl,
    'file=s'     => \$cfg_file,
    'port=i'     => \$port,
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

DEBUG("create new Captive::Portal::TestServer object ...");
my $server = Captive::Portal::TestServer->new($port);


$server->{capo}        = $capo;
$server->{static_root} = $capo->cfg->{DOCUMENT_ROOT};

INFO("You can connect the server on Port: $port");
$server->run;

sub usage {
    die "$Script [-p port] [-f capo.cfg] [-l log4perl.cfg]\n";
}

=head1 AUTHOR

Karl Gaissmaier, C<< <gaissmai at cpan.org> >>

=head1 LICENSE AND COPYRIGHT

Copyright 2010-2011 Karl Gaissmaier, all rights reserved.

This distribution is free software; you can redistribute it and/or modify it
under the terms of either:

a) the GNU General Public License as published by the Free Software
Foundation; either version 2, or (at your option) any later version, or

b) the Artistic License version 2.0.

=cut
