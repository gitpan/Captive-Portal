#!/usr/bin/env perl

use strict;
use warnings;

our $VERSION = '2.10';

=head1 NAME

capo.fcgi - (f)cgi script for Captive::Portal

=head1 ABSTRACT

(f)cgi script to handle http(s) requests for Captive::Portal.

=head1 DESCRIPTION

This script is started by the HTTP server. It can be used as a simple CGI script, but for heavy loaded sites FastCGI is strongly recommended.

=cut

use sigtrap qw(die untrapped normal-signals);

use FindBin qw($Bin);
use lib "$Bin/../lib";

use Log::Log4perl qw(:easy);
use CGI::Fast;
use Captive::Portal;

$ENV{PATH} = '/sbin:/bin:/usr/sbin:/usr/bin';

=head1 CONFIGURATION

=over 4

=item B<Captive::Portal config file>

By default

    $ENV{CAPTIVE_PORTAL_CONFIG} ||
    $Bin/../etc/local/config.pl ||
    $Bin/../etc/config.pl

=item B<Log::Log4perl config file>

By default

    $ENV{CAPTIVE_PORTAL_LOG4PERL}   ||
    $Bin/../etc/local/log4perl.conf ||
    $Bin/../etc/log4perl.conf

=back

=cut

#####################################################################
# search for config files in default places
#####################################################################

my $cfg_file =
     $ENV{CAPTIVE_PORTAL_CONFIG}
  || -e "$Bin/../etc/local/config.pl" && "$Bin/../etc/local/config.pl"
  || -e "$Bin/../etc/config.pl" && "$Bin/../etc/config.pl";

my $log4perl = $ENV{CAPTIVE_PORTAL_LOG4PERL}
  || -e "$Bin/../etc/local/log4perl.conf"
  && "$Bin/../etc/local/log4perl.conf"
  || -e "$Bin/../etc/log4perl.conf" && "$Bin/../etc/log4perl.conf";

if ( $log4perl && -f $log4perl ) {
    Log::Log4perl->init($log4perl);
}
else {
    Log::Log4perl->easy_init($DEBUG);
}

#####################################################################
# create Captive::Portal object and enter request loop
#####################################################################

DEBUG("create new Captive::Portal object ...");
my $capo = Captive::Portal->new( cfg_file => $cfg_file );

# main-loop
while ( my $q = CGI::Fast->new ) {
    $capo->run($q);
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

The full text of the license can be found in the LICENSE file included
with this distribution.

=cut
