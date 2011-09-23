use strict;
use warnings;

use Test::More;
use Try::Tiny;

use_ok('Captive::Portal');

my ( $capo, $session, $ip, $mac, $error );

ok( $capo = Captive::Portal->new( cfg_file => 't/etc/ok.pl' ),
    'successfull parse t/etc/ok.pl' );

undef $error;
try { $capo->clear_sessions_from_disk } catch { $error = $_ };
ok( !$error, 'cleared all sessions' );

$session = _mk_session();
$ip     = $session->{IP};

my %lock_options = (
    key      => $ip,
    blocking => 0,
    shared   => 0,
);

my $lock_handle;

undef $error;
try { $lock_handle = $capo->get_session_lock_handle(%lock_options) }
catch { $error = $_ };
ok( !$error, 'get session lock handle' );

is( $capo->read_session_handle($lock_handle), undef, 'read empty session' );

undef $error;
try { $capo->write_session_handle( $lock_handle, $session ) }
catch { $error = $_ };
ok( !$error, 'set session' );

is_deeply( $capo->read_session_handle($lock_handle), $session, 'check session' );

undef $error;
try { $capo->write_session_handle( $lock_handle, $session ) }
catch { $error = $_ };
ok( !$error, 'set same session again');

is_deeply( $capo->read_session_handle($lock_handle),
    $session, 'check session again' );

undef $error;
try { $capo->clear_sessions_from_disk } catch { $error = $_ };
ok( !$error, 'cleared all sessions' );

is( $capo->list_sessions_from_disk, 0, 'cleared all sessions' );

done_testing(11);

sub _mk_session {
    my $subnet = int( rand(256) );
    my $host   = int( rand(256) );
    my $byte   = unpack( 'H2', int( rand(256) ) );

    my $ip  = "10.10.$subnet.$host";
    my $mac = "00:01:02:03:04:$byte";

    my $session = {
        IP            => $ip,
        MAC           => $mac,
        STATE         => 'active',
        USERNAME      => 'test',
        USER_AGENT    => 'test',
    };

    return $session;
}

