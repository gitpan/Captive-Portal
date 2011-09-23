package Captive::Portal::Role::Utils;

use strict;
use warnings;

=head1 NAME

Captive::Portal::Role::Utils - common utils for Captive::Portal

=cut

our $VERSION = '2.10';

use Log::Log4perl qw(:easy);
use Capture::Tiny qw(capture);
use Try::Tiny;
use Scalar::Util qw(looks_like_number);
use Time::HiRes qw(usleep ualarm);
use Socket qw(inet_ntoa);
use Net::hostent;
use Template::Exception;
use Fcntl qw(:flock O_CREAT O_RDWR);
use FileHandle qw();

use Role::Basic;
requires qw(cfg);

=head1 DESCRIPTION

Utility roles needed by other modules. All roles die on error.

=head1 ROLES

=over 4

=item $capo->get_arp_table()

Open, read and parse I</proc/net/arp>.

Return hashref with ipv4 addresses as keys and MAC-addresses as values.

=cut

sub get_arp_table {
    my $self = shift;

    DEBUG 'open /proc/net/arp';

    open ARP, '<', '/proc/net/arp'
      or LOGDIE "Couldn't open /proc/net/arp: $!\n";

    my @proc_net_arp = <ARP>
      or LOGDIE "Couldn't read /proc/net/arp: $!\n";

    # regex for ipv4 address
    my $ipv4_rx = qr/\d{1,3} \. \d{1,3} \. \d{1,3} \. \d{1,3}/x;

    # regex for MAC address matching
    my $hex_digit_rx = qr/[A-F,a-f,0-9]/;
    my $mac_rx       = qr/(?:$hex_digit_rx{2}:){5} $hex_digit_rx{2}/x;

    my $arp_tbl = {};
    foreach my $line (@proc_net_arp) {

        # 10.10.1.2    0x1     0x2    00:00:01:02:03:04     *        eth0

        my ( $ip, $mac ) = (
            $line =~ m/
		^
		($ipv4_rx)               # IP-addr
		\s+ 0x\d+ \s+ 0x2 \s+
		($mac_rx)                # MAC-addr
		\s+ .*
		/x
        );

        # arp flag 0x02 invalid or parse error
        next unless defined $ip && defined $mac;

        $ip = $self->normalize_ip($ip);
        $arp_tbl->{$ip} = uc $mac;
    }

    return $arp_tbl;
}

=item $capo->ip2hex($ip)

Helper method, convert ipv4 address to hexadecimal representation.

Example:
 '10.1.2.254' -> '0a0102fe'

=cut

sub ip2hex {
    my $self = shift;
    my $ip   = shift
      or LOGDIE 'missing param ip';

    return unpack( 'H8', pack( 'C4', split( /\./, $ip ) ) );
}

=item $capo->normalize_ip($ip)

Helper method, normalize ip adresses, strip leading zeros in octets.

Example:
 '012.2.3.000' -> '12.2.3.0'

=cut

sub normalize_ip {
    my $self = shift;

    my $ip = shift
      or LOGDIE "FATAL: missing param 'ip',";

    my @octets = split /\./, $ip;

    LOGDIE "FATAL: couldn't split '$ip' into 4 octets,"
      if scalar @octets != 4;

    # delete leading zeros in octets
    # (side effect: wrap octets 256 -> 0, ...), should not happen
    my $ip_packed_unpacked = join '.', unpack 'C4', pack 'C4', @octets;

    return $ip_packed_unpacked;
}

=item $capo->drop_privileges()

Running under root, like normal cronjobs do, should drop to the same uid/gid as the http daemon (and fcgi script). uid/gid is taken from config as RUN_USER/RUN_GROUP.

=cut

sub drop_privileges {
    my $self = shift;

    my $user = $self->cfg->{RUN_USER}
      or LOGDIE "FATAL: missing 'RUN_USER' in cfg file,";

    my $group = $self->cfg->{RUN_GROUP}
      or LOGDIE "FATAL: missing 'RUN_GROUP' in cfg file,";

    DEBUG "drop privileges to $user:$group";

    ########
    # resolve user to username and/or uid
    my ( $uname, $uid );

    if ( $user =~ m/^\d+$/ ) {
        $uname = getpwuid($user);
        $uid   = $user;
    }
    else {
        $uid   = getpwnam($user);
        $uname = $user;
    }

    unless ( defined($uname) and defined($uid) ) {
        LOGDIE "user '$user' not known to system\n";
    }

    ########
    # resolve group to groupname and/or gid
    my ( $gname, $gid );

    if ( $group =~ m/^\d+$/ ) {
        $gname = getgrgid($group);
        $gid   = $group;
    }
    else {
        $gid   = getgrnam($group);
        $gname = $group;
    }

    unless ( defined($gname) and defined($gid) ) {
        LOGDIE "group '$group' not known to system\n";
    }

    # switch to user:group not needed
    # already running under required uid:gid
    return if $> == $uid && $) == $gid;

    DEBUG "switch GID and EGID to $gid";

    $( = $) = $gid;
    LOGDIE "cannot change group to '$group': $!\n"
      if $) != $gid;

    DEBUG "switch UID and EUID to $uid";

    $< = $> = $uid;
    LOGDIE "cannot change user to '$user': $!\n"
      if $> != $uid;

}

=item $capo->gettext($msg_nr)

Poor mans gettext. Returns language specific text from config hash for message number.

=cut

sub gettext {
    my $self = shift;
    my $text = shift
      or LOGDIE 'missing param text';

    my $i18n_text =
      $self->cfg->{I18N_MSG_CATALOG}{$text}{ $self->{CTX}{LANG} };

    unless ($i18n_text) {
        ERROR "missing I18N text for '$text' in lang: $self->{CTX}{LANG}";
        $i18n_text = "missing '$text' for lang '$self->{CTX}{LANG}'";
    }

    return $i18n_text;
}

=item $capo->choose_language()

Parses the HTTP header 'Accept-Language' and returns an appropriate language from the configured languages or the fallback language.

=cut

sub choose_language {
    my $self  = shift;
    my $query = $self->{CTX}{QUERY};

    my $http_accept_language = $query->http('HTTP_ACCEPT_LANGUAGE')
      || '';
    DEBUG("HTTP-Accept-Language is: $http_accept_language");

    ###
    # parse the HTTP header
    #
    # Example header: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3
    #
    my $default_quant = 1;
    my %languages;

    foreach my $item ( split( /,/, $http_accept_language ) ) {
        $item =~ s/\s//g;    #strip spaces

        my ( $lang, $quant ) = split( /;q=/, $item );

        # don't use fine-granular language subtags for CaPo
        # cutoff the language subtags: de-AT => de
        $lang =~ s/-.*//;

        # skip silently the wildcard '*'
        next if $lang eq '*';

        # parse error, silently skip this language item
        next if defined $quant && ( not looks_like_number($quant) );

        # set the default language quantifier
        unless ( defined $quant ) {

            # give the first one a quant of 1
            $quant = $default_quant;

            # and the next without quantification .001 less
            $default_quant -= 0.001;
        }

        # first language entry
        unless ( $languages{$lang} ) {
            $languages{$lang} = $quant;
            next;
        }

        # override language entry with higher quant
        if ( $quant > $languages{$lang} ) {
            $languages{$lang} = $quant;
            next;
        }

    }

    # sort in descending quantification order
    my @accept_languages_sorted =
      sort { $languages{$b} <=> $languages{$a} } keys %languages;

    DEBUG( 'language prefered order is: '
          . join( ' > ', @accept_languages_sorted ) );

    DEBUG( 'configured languages: '
          . join( ' ', @{ $self->cfg->{I18N_LANGUAGES} } ) );

    # look for accepted language in configured languages
    my $choosen_language;
    foreach my $lang (@accept_languages_sorted) {
        if ( grep m/\A\Q$lang\E\Z/, @{ $self->cfg->{I18N_LANGUAGES} } ) {
            $choosen_language = $lang;
            last;    # ready
        }
    }

    return $choosen_language || $self->cfg->{I18N_FALLBACK_LANG};
}

=item $capo->run_cmd(@cmd_with_options, [$run_cmd_options])

Wrapper to run external commands, capture and return (stdout/stderr).

Last optional parameter item is a hashref with options for run_cmd itself:
    {
        timeout           => 500_000,    # default 500_000us,
        ignore_exit_codes => [],         # exit codes without exception
    }

If the external command doesn't return after I<timeout>, the command is interrupted and an exception is thrown.

Exit codes != 0 and not defined in I<ignore_exit_codes> throw exceptions.

Remark: Can't use other CPAN modules to run external commands and capture stdout and stderr due to the buggy tie implementation of FCGI.

=cut

sub run_cmd {
    my $self = shift;
    my @cmd  = @_;
    LOGDIE "Paramter missing," unless scalar @cmd;

    my $options = {
        timeout           => 500_000,    # 0.5s
        ignore_exit_codes => [],
    };

    # options from caller override defaults
    if ( ref $cmd[-1] eq 'HASH' ) {
        $options = { %$options, %{ pop @cmd } };
    }

    my $timeout           = $options->{timeout};
    my $ignore_exit_codes = $options->{ignore_exit_codes};

    DEBUG("try to run: @cmd");
    my ( $old_alarm, $error, $stdout, $stderr );
    try {

        # get rid of the 'No child processes', see perldoc perlipc
        local $SIG{CHLD} = 'DEFAULT';

        local $SIG{ALRM} = sub { die "timeout running cmd: '@cmd'," };

	###############################
        # get rid of some Capture::Tiny limitations with FCGI
        # the problem is the buggy FCGI tie implementation for filehandles

        local *STDIN;
        local *STDOUT;
        local *STDERR;

        open( STDIN,  '<&=0' );
        open( STDOUT, '>>&=1' );
        open( STDERR, '>>&=2' );
	#
	###############################

        # start/stop watchdog around system()
        $old_alarm = ualarm $timeout || 0;
        ( $stdout, $stderr ) = capture { system(@cmd) };

	#################################
        # normalize exit code, see perldoc -f system
        my $exit_code = $?;

        if ( $exit_code == -1 ) {
            die $! || $stderr;
        }
        elsif ( $exit_code & 127 ) {
            die 'child died with signal ' . ( $exit_code & 127 );
        }
        else {
            $exit_code = $exit_code >> 8;
        }
	#
	#################################

        # something went wrong with system, shall we ignore it
        if ( $exit_code != 0 ) {
            die( $! || $stderr )
              unless grep { $exit_code == $_ } @$ignore_exit_codes;
        }

        # restart old alarm
        ualarm $old_alarm;
    }
    catch {    # catched an exception in try {}

        # restart old alarm
        ualarm $old_alarm;

        # propagate exception
        $error = $_;
    };

    die $error if $error;

    return ( $stdout, $stderr );
}

=item $capo->ipv4_aton($hosts)

Template callback converting DNS name(s) to ip address(es), see perldoc Template::Manual::Variables. With this helper, DNS-names in firewall templates are translated to ipv4 adresses.

Example:
 '10.10.10.10'  ->  '10.10.10.10'

 'www.acme.rog' -> [10.1.2.3, 10.1.2.4, 10.1.2.5, ...]

 [ftp.uni-ulm.de, www.uni-ulm.de] -> [134.60.1.5, 134.60.1.25]

=cut

sub ipv4_aton {
    my @hosts = @_
      or die Template::Exception->new( 'ipv4_aton',
        "missing param 'hosts'\n" );

    # explode array refs
    my @host_list;
    foreach my $host (@hosts) {
        if ( not ref $host ) {
            push @host_list, $host;
        }
        elsif ( ref $host eq 'ARRAY' ) {
            push @host_list, @$host;
        }
        else {
            die Template::Exception->new( 'ipv4_aton',
                "param 'hosts' must be a SCALAR or ARRAY_REF\n" );
        }
    }

    my @addr_list = ();
    foreach my $host (@host_list) {

        # got an IP address instead of DNS name
        if ( $host =~ m/^[.0-9]+$/ ) {

            # push it to addr_list regardless of DNS entry
            push @addr_list, $host;
            next;
        }

        my $hostent;
        unless ( $hostent = gethost($host) ) {
            die Template::Exception->new( 'ipv4_aton',
                "No such host: '$host'\n" );
        }

        foreach my $packed_ip ( @{ $hostent->addr_list } ) {
            push @addr_list, inet_ntoa($packed_ip);
        }
    }

    scalar @addr_list == 1
      ? return $addr_list[0]
      : return \@addr_list;
}

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

# vim: sw=4

