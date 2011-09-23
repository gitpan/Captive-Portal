use strict;
use warnings;

use Test::More;
use Try::Tiny;

use_ok('Captive::Portal::Role::Utils');

my ( $stdout, $stderr, $error );

try {
    Captive::Portal::Role::Utils->run_cmd(qw(sleep 1), { timeout => 2_000_000 } );
}
catch { $error = $_ };
ok( !$error, "external cmd 'sleep 1'" );

undef $error;
try { Captive::Portal::Role::Utils->run_cmd( qw(sleep 2), { timeout => 1_000_000 } ) }
catch { $error = $_ };
like( $error, qr/timeout/i, "throws error message like 'timeout'" );

undef $error;
try {
    Captive::Portal::Role::Utils->run_cmd( qw(ls pipapo),
        { ignore_exit_codes => [1,2], } );
}
catch { $error = $_ };
ok( !$error, "ignore exit_codes" );
#diag explain $error;

undef $error;
try { Captive::Portal::Role::Utils->run_cmd(qw(pipapo)) } catch { $error = $_ };
like(
    $error,
    qr/Can't exec .pipapo./i,
    "throws error message like 'no such file ... '"
);
#diag explain $error;

( $stdout, $stderr ) = Captive::Portal::Role::Utils->run_cmd(qw(echo asdf));
like( $stdout, qr/^asdf\s*/, 'stdout for external cmd' );

( $stdout, $stderr ) =
  Captive::Portal::Role::Utils->run_cmd( qw(perl -e), 'warn "foobarbaz\n"' );
like( $stderr, qr/^foobarbaz$/, 'stderr for external cmd' );

my @ip_addresses = qw(010.100.010.001 00001.1.00002.0004 1.2.3.4);
my @expected     = qw(10.100.10.1 1.1.2.4 1.2.3.4);

@ip_addresses =
  map { Captive::Portal::Role::Utils->normalize_ip($_) } @ip_addresses;

is_deeply( \@ip_addresses, \@expected, 'ip addr normalization' );

done_testing(8);
