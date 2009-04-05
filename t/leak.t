# Resources (mem/fd) shouldn't leak.
use warnings;
use strict;
use t::share;

if ($INC{'Devel/Cover.pm'}) {
    plan skip_all => 'unable to test under Devel::Cover';
}
plan tests => 4;

leaktest('create_client_stream');
leaktest('create_server_stream');

sub create_client_stream {
    IO::Stream->new({
        host        => '127.0.0.1',
        port        => 1234,
        cb          => sub {},
        wait_for    => 0,
        plugin      => [
            ssl         => IO::Stream::MatrixSSL::Client->new({}),
        ],
    })->close();
}

sub create_server_stream {
    IO::Stream->new({
        host        => '127.0.0.1',
        port        => 1234,
        cb          => sub {},
        wait_for    => 0,
        plugin      => [
            ssl         => IO::Stream::MatrixSSL::Server->new({
                crt         => 't/cert/testsrv.crt',
                key         => 't/cert/testsrv.key',
            }),
        ],
    })->close();
}

sub leaktest {
    my $test = shift;
    my %arg  = (init=>10, test=>1000, max_mem_diff=>100, diag=>1, @_);
    my $code = do { no strict 'refs'; \&$test };
    $code->() for 1 .. $arg{init};
    my $mem = MEM_used();
    my $fd  = FD_used();
    $code->() for 1 .. $arg{test};
    diag sprintf "---- MEM\nWAS: %d\nNOW: %d\n", $mem, MEM_used() if $arg{diag};
    ok( abs(MEM_used() - $mem) < $arg{max_mem_diff},  "MEM: $test" );
    is(FD_used(), $fd,                                " FD: $test" );
}

sub MEM_used {
    open my $f, '<', '/proc/self/status';
    my $status = join q{}, <$f>;
    return ($status =~ /VmRSS:\s*(\d*)/)[0];
};

sub FD_used {
    opendir my $fd, '/proc/self/fd' or croak "opendir: $!";
    return @{[ readdir $fd ]} - 2;
};

