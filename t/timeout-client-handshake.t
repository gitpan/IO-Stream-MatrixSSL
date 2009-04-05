# Write timeout.
use warnings;
use strict;
use IO::Stream::MatrixSSL::const;
BEGIN {
    *IO::Stream::MatrixSSL::const::TOHANDSHAKE = sub () { 0.1 };
}
use t::share;


@CheckPoint = (
    [ 'client', RESOLVED, undef             ], 'client: RESOLVED',
    [ 'client', CONNECTED, undef            ], 'client: CONNECTED',
    [ 'client', 0, 'ssl handshake timeout'  ], 'client: ssl handshake timeout',
);
plan tests => @CheckPoint/2;



my $srv_sock = tcp_server('127.0.0.1', 4444);
IO::Stream->new({
    host        => '127.0.0.1',
    port        => 4444,
    cb          => \&client,
    wait_for    => RESOLVED|CONNECTED|SENT,
    out_buf     => 'test',
    plugin      => [
        ssl         => IO::Stream::MatrixSSL::Client->new({}),
    ],
});

EV::loop;


sub client {
    my ($io, $e, $err) = @_;
    checkpoint($e, $err);
    EV::unloop if $err;
}
