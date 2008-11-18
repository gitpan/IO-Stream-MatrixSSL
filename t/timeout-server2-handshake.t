# Write timeout.
use warnings;
use strict;
use IO::Stream::MatrixSSL::const;
BEGIN {
    *IO::Stream::MatrixSSL::const::TOHANDSHAKE = sub () { 0.1 };
}
use t::share;


@CheckPoint = (
    [ 'server', 0, 'ssl handshake timeout'  ], 'server: ssl handshake timeout',
);
plan tests => @CheckPoint/2;



my $srv_sock = tcp_server('127.0.0.1', 4444);
IO::Stream->new({
    fh          => tcp_client('127.0.0.1', 4444),
    cb          => \&server,
    wait_for    => RESOLVED|CONNECTED|SENT,
    out_buf     => 'test',
    plugin      => [
        ssl         => IO::Stream::MatrixSSL::Server->new({
            crt         => 't/cert/testsrv.crt',
            key         => 't/cert/testsrv.key',
        }),
    ],
});

EV::loop;


sub server {
    my ($io, $e, $err) = @_;
    checkpoint($e, $err);
    EV::unloop if $err;
}

