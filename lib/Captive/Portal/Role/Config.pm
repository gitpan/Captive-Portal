package Captive::Portal::Role::Config;

use strict;
use warnings;

=head1 NAME

Captive::Portal::Role::Config - Config reader for Captive::Portal

=head1 DESCRIPTION

Config file parser and storage for cfg hash.

=cut

our $VERSION = '2.10';

use Log::Log4perl qw(:easy);
use FindBin qw($Bin);
use File::Spec::Functions qw(splitdir rootdir catfile catdir);

use Role::Basic;

# just bin/../ => bin
my @bin_parts = splitdir($Bin);
pop(@bin_parts);

use constant TRUE  => 1;
use constant FALSE => 0;

use constant ON  => 1;
use constant OFF => 0;

use constant YES => 'yes';
use constant NO  => '';

use vars qw($APP_NAME $APP_DIR);

$APP_NAME = 'capo';
$APP_DIR  = catdir(@bin_parts);

# SINGLETON
my $cfg_hash = {};

my %pre_defaults = (
    DOCUMENT_ROOT => catdir( $APP_DIR, 'static' ),

    TEMPLATE_INCLUDE_PATH => catdir( $APP_DIR, 'templates', 'local' ) . ':'
      . catdir( $APP_DIR, 'templates', 'orig' ),

    SESSIONS_DIR => catdir( rootdir(), 'var', 'cache', $APP_NAME ),

    RUN_USER  => 'wwwrun',
    RUN_GROUP => 'www',

    SECURE_COOKIE         => ON,
    SESSION_MAX           => 2 * 24 * 60 * 60,    # 2 days
    KEEP_OLD_STATE_PERIOD => 1 * 60 * 60,         # 1h

    IDLE_TIME     => 10 * 60,                     # 10min before set to idle
    USE_FPING     => ON,                          # trigger idle clients
    FPING_OPTIONS => [qw(-c 1 -i 1 -t 1 -q)],     # SuSe default

    I18N_LANGUAGES     => [ 'en', ],
    I18N_FALLBACK_LANG => 'en',
);

# Role::Basic exports ALL subroutines, there is currently no other way to
# prevent exporting private methods, sigh
#
my ($_priv_post_defaults, $_priv_check_cfg);

=head1 ROLES

=over

=item $capo->parse_cfg_file($filename)

Parse config file, merge with defaults. Die on error.

=cut

sub parse_cfg_file {
    my $self     = shift;
    my $cfg_file = shift;
    LOGDIE "missing parameter 'config_file'" unless defined $cfg_file;

    DEBUG "preset cfg_hash with default values";
    $cfg_hash = {%pre_defaults};

    DEBUG "parse config file $cfg_file";
    my $parsed_cfg_file = do $cfg_file;

    # check the config file for syntactic errors
    LOGDIE "couldn't parse $cfg_file: $@" if $@;
    LOGDIE "couldn't do $cfg_file: $!"
      unless defined $parsed_cfg_file;
    LOGDIE "couldn't run $cfg_file" unless $parsed_cfg_file;

    DEBUG "merge parsed values with preset default values to cfg_hash";
    $cfg_hash = { %$cfg_hash, %$parsed_cfg_file };

    $self->$_priv_check_cfg();

    $self->$_priv_post_defaults();

    return 1;
}

=item $capo->cfg()

Getter, return a copy of the config hashref.

=cut

sub cfg { return {%$cfg_hash}; }

#
# Add some defaults after reading cfg file. Must be postponed to
# interpolate of already set params.
#

$_priv_post_defaults = sub {

    # defined as anonymous sub,
    # else Role::Basic would export this as role, sigh!

    DEBUG "add post_parse config default values, if needed";

    unless ( exists $cfg_hash->{LOCK_FILE} ) {
        $cfg_hash->{LOCK_FILE} =
          catfile( $cfg_hash->{SESSIONS_DIR}, 'capo-ctl.lock' );
    }
};

#
# semantic params validation of cfg_hash
#

$_priv_check_cfg = sub {

    # defined as anonymous sub,
    # else Role::Basic would export this as role, sigh!

    DEBUG "do cfg_hash params validation";

    # check the config file for sematic errors and warnings
    if ( $cfg_hash->{BOILERPLATE} ) {
        LOGDIE 'FATAL: the config file is in BOILERPLATE state';
    }

    unless ( $cfg_hash->{SESSIONS_DIR} ) {
        LOGDIE 'FATAL: missing SESSIONS_DIR in cfg file';
    }

    if ( $cfg_hash->{MOCK_MAC} ) {
        ERROR "uncomment 'MOCK_MAC' for production in cfg file";
    }

    if ( $cfg_hash->{MOCK_FIREWALL} ) {
        ERROR "uncomment 'MOCK_FIREWALL' for production in cfg file";
    }

    if ( $cfg_hash->{MOCK_AUTHEN} ) {
        ERROR "uncomment 'MOCK_AUTHEN' for production in cfg file";
    }
    else {
        ERROR 'missing Authen::Simple modules in cfg file'
          unless $cfg_hash->{'AUTHEN_SIMPLE_MODULES'};
    }

    unless ( $cfg_hash->{ADMIN_SECRET} ) {
        ERROR 'missing ADMIN_SECRET in cfg file';
    }

    unless ( $cfg_hash->{IPTABLES}{capture_if} ) {
        ERROR "missing 'capture_if' in cfg file";
    }

    unless ( $cfg_hash->{IPTABLES}{capture_net} ) {
        ERROR "missing 'capture_net' in cfg file";
    }

    unless ( $cfg_hash->{IPTABLES}{capture_ports} ) {
        ERROR "missing 'capture_ports' in cfg file";
    }

    unless ( $cfg_hash->{IPTABLES}{redirect_port} ) {
        ERROR "missing 'redirect_port' in cfg file";
    }
};

1;

=back

=head1 AUTHOR

Karl Gaissmaier, C<< <gaissmai at cpan.org> >>

=head1 LICENSE AND COPYRIGHT

Copyright 2010, 2011 Karl Gaissmaier, all rights reserved.

This distribution is free software; you can redistribute it and/or modify it
under the terms of either:

a) the GNU General Public License as published by the Free Software
Foundation; either version 2, or (at your option) any later version, or

b) the Artistic License version 2.0.

The full text of the license can be found in the LICENSE file included
with this distribution.

=cut

#vim: sw=4
