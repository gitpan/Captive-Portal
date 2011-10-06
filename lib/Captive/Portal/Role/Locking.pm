package Captive::Portal::Role::Locking;

use strict;
use warnings;

=head1 NAME

Captive::Portal::Role::Locking - lock handling for Captive::Portal

=cut

our $VERSION = '2.15';

use Log::Log4perl qw(:easy);
use Try::Tiny;
use Time::HiRes qw(usleep ualarm);
use Fcntl qw(:flock O_CREAT O_RDWR);
use FileHandle qw();

use Role::Basic;

=head1 DESCRIPTION

CaPo locking and transaction handling. 

=head1 ROLES

=over 4

=item $capo->get_lock_handle(%named_params)

Returns a filehandle with the requested lock assigned. There is no unlock, after destroying the filehandle the file is automatically closed and the lock released.

Named parameters:

 file     => filename to lock, created if not existing
 shared   => shared lock, defaults to exclusive lock
 blocking => blocking lock request, defaults to blocking
 try      => number of retries in nonblocking mode, defaults to 1 retry
 timeout  => timeout in blocking mode, defaults to 1s

=cut 

sub get_lock_handle {
    my $self = shift;
    my %opts = @_;

    LOGDIE "missing param 'file'" unless exists $opts{file};

    my $file = delete $opts{file};

    DEBUG "lock requested for $file";

    # make lexical scoped filehandle

    my $lock_handle = FileHandle->new( $file, O_RDWR | O_CREAT )
      or LOGDIE "Can't open $file: $!";

    my $fileno = $lock_handle->fileno or LOGDIE "Can't read fileno: $!";

    DEBUG "fd=$fileno, filehandle created";

    # defaults
    $opts{shared}   = 0 unless exists $opts{shared};
    $opts{blocking} = 1 unless exists $opts{blocking};
    $opts{try}      = 1 unless exists $opts{try};

    # 1_000_000us -> 1s
    $opts{timeout} = 1_000_000 unless exists $opts{timeout};

    my $mode;
    if ( $opts{shared} ) {
        DEBUG "fd=$fileno, lock mode is SHARED";

        $mode = LOCK_SH;
    }
    else {
        DEBUG "fd=$fileno, lock mode is EXCLUSIVE";

        $mode = LOCK_EX;
    }

    # try to get the lock:
    #   - blocking with timeout
    #   - nonblocking with retry

    if ( $opts{blocking} ) {

        DEBUG "fd=$fileno, lock mode is BLOCKING";
        DEBUG "fd=$fileno, timeout is $opts{timeout} us";

        my $old_alarm;
        my $error;

        try {

            local $SIG{ALRM} = sub {
                die "fd=$fileno, timeout locking $file\n";
            };

            $old_alarm = ualarm $opts{timeout} || 0;

            flock $lock_handle, $mode
              or die "fd=$fileno, couldn't lock $file: $!\n";

            DEBUG "fd=$fileno, LOCKED";

            # reset alarm
            ualarm $old_alarm;
        }
        catch {

            # reset alarm
            ualarm $old_alarm;

            # propagate error
            $error = $_;
        };

        die "$error\n" if $error;

        return $lock_handle;

    }
    else {

        my $error;

        DEBUG "fd=$fileno, lock mode is NONBLOCKING";
        $mode |= LOCK_NB;

        DEBUG "fd=$fileno, lock retry $opts{try}";
	my $retry = $opts{try};

        while ( $retry-- > 0 ) {

            undef $error;

            try {
                flock $lock_handle, $mode
                  or die "fd=$fileno, couldn't lock $file after $opts{try} retries: $!\n";

		DEBUG "fd=$fileno, LOCKED";
            }
            catch { $error = $_; };

            if ($error) {
                DEBUG $error;
                DEBUG "fd=$fileno, lock retries left: $retry";

                # sleep for 1ms
                usleep 1_000;

                next;
            }

            return $lock_handle;
        }

        die "$error\n";

    }
}

1;

=back

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

# vim: sw=4

