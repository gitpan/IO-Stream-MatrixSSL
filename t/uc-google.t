# Use case: HTTP GET until EOF
use warnings;
use strict;
use t::share;

if (CFG_ONLINE ne 'y') {
    plan skip_all => 'online tests disabled';
}

IO::Stream->new({
#    fh          => tcp_client('www.google.com', 443),
    host        => 'www.google.com',
    port        => 443,
    cb          => \&client,
    wait_for    => EOF,
    out_buf     => "GET / HTTP/1.0\nHost: www.google.com\n\n",
    in_buf_limit=> 102400,
    plugin      => [
        ssl         => IO::Stream::MatrixSSL::Client->new({
            cb          => \&validate,
        }),
    ],
});

@CheckPoint = (
    [ 'validate',   'www.google.com'], 'validate: got certificate for www.google.com',
    [ 'client',     EOF             ], 'client: got eof',
);
plan tests => 1 + @CheckPoint/2;

EV::loop;

sub validate {
    my ($certs, $ssl, $io) = ($_[0], @{ $_[1] });
    checkpoint($certs->[0]{subject}{commonName});
    return 0;
}

sub client {
    my ($io, $e, $err) = @_;
    checkpoint($e);
    like($io->{in_buf}, qr{\AHTTP/\d+\.\d+ }, 'got reply from web server');
    die "server error\n" if $e != EOF || $err;
    EV::unloop;
}

