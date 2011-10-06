package Captive::Portal::TestServer;

use strict;
use warnings;

=head1 NAME

Captive::Portal::TestServer - simple HTTP Server for Captive::Portal tests

=cut

our $VERSION = '2.15';

use parent 'HTTP::Server::Simple::CGI';
use HTTP::Server::Simple::Static qw(serve_static);
use CGI qw();

=head1 METHODS

=over

=item handle_request

Simple wrapper to mix static and dynamic requests in one handler.

=cut

sub handle_request {
    my $self = shift;
    my $cgi = shift or die 'param CGI missing, stopped';

    $cgi->nph(1);

    # no setters/getters for this simple wrapper defined
    my $capo = $self->{capo} or die 'capo undefined, stopped';
    my $static_root = $self->{static_root}
	or die 'static_root undefined, stopped';

    # handle static if found
    return if $self->serve_static( $cgi, $static_root );

    # no static file found, handle via CaPo
    return $capo->run($cgi);
}

# to noisy
sub print_banner {};

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
