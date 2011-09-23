use strict;
use warnings;

use Test::More;

BEGIN {
    local $^W;

    no warnings 'redefine';

    my @MODULES = qw(Test::WWW::Mechanize::CGI);

    # Load the testing modules
    foreach my $MODULE (@MODULES) {
        eval "use $MODULE";
        if ($@) {
            $ENV{RELEASE_TESTING}
              ? die(
                "Failed to load required release-testing module $MODULE")
              : plan( skip_all => "$MODULE not available for testing" );
        }
    }
}

# enable this code fragment to get DEBUG logging for this tests
=pod

my $log4perl_conf = <<EO_CONF;
log4perl.logger                 = DEBUG, screen
log4perl.appender.screen   = Log::Log4perl::Appender::Screen
log4perl.appender.screen.layout   = Log::Log4perl::Layout::PatternLayout
log4perl.appender.screen.layout.ConversionPattern = [%04R ms] [%5P pid] [%p{1}] [%15.15M{1}] %m %n
EO_CONF

use Log::Log4perl;
Log::Log4perl->init(\$log4perl_conf);

=cut

use_ok('CGI');

use_ok('Captive::Portal');

ok( my $capo = Captive::Portal->new( cfg_file => 't/etc/ok.pl' ),
    'successfull parse t/etc/ok.pl' );

my $mech = Test::WWW::Mechanize::CGI->new;
$mech->cgi( sub { $capo->run( CGI->new ); } );
$mech->get_ok(q{http://localhost});

$mech = Test::WWW::Mechanize::CGI->new;
$mech->cgi( sub { $capo->run( CGI->new ); } );
$mech->get_ok(q{http://localhost?username=fake;password=foo;login=1});

$mech = Test::WWW::Mechanize::CGI->new;
$mech->cgi( sub { $capo->run( CGI->new ); } );
$mech->get_ok(q{http://localhost/status});

$mech = Test::WWW::Mechanize::CGI->new;
$mech->cgi( sub { $capo->run( CGI->new ); } );
$mech->get_ok(q{http://localhost/status?admin_secret=my-secret});

$mech = Test::WWW::Mechanize::CGI->new;
$mech->cgi( sub { $capo->run( CGI->new ); } );
$mech->get_ok(q{http://localhost?logout=1});

#diag explain $mech;

done_testing();

