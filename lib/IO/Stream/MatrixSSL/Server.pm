package IO::Stream::MatrixSSL::Server;

use warnings;
use strict;
use Carp;

use version; our $VERSION = qv('1.0.0');    # update POD & Changes & README

# update DEPENDENCIES in POD & Makefile.PL & README
use IO::Stream::const;
use IO::Stream::MatrixSSL::const;
use Crypt::MatrixSSL 1.83;
use Scalar::Util qw( weaken );

use base qw( IO::Stream::MatrixSSL );


sub new {
    my ($class, $opt) = @_;
    croak '{crt} and {key} required'
        if !defined $opt->{crt} || !defined $opt->{key};
    my $self = bless {
        crt         => undef,       # filename(s) with server certificate(s)
        key         => undef,       # filename with server private key
        pass        => undef,       # password to decrypt private key
        %{$opt},
        out_buf     => q{},                 # modified on: OUT
        out_pos     => undef,               # modified on: OUT
        out_bytes   => 0,                   # modified on: OUT
        in_buf      => q{},                 # modified on: IN
        in_bytes    => 0,                   # modified on: IN
        ip          => undef,               # modified on: RESOLVED
        is_eof      => undef,               # modified on: EOF
        _ssl        => undef,       # MatrixSSL 'session' object
        _ssl_keys   => undef,       # MatrixSSL 'keys' object
        _handshaked => 0,           # flag, will be true after handshake
        _want_write => undef,
        _t          => undef,
        _cb_t       => undef,
        }, $class;
    my $this = $self;
    weaken($this);
    $self->{_cb_t} = sub { $this->T() };
    # Initialize SSL.
    # TODO OPTIMIZATION Cache {_ssl_keys}.
    matrixSslReadKeys($self->{_ssl_keys}, $self->{crt}, $self->{key},
        $self->{pass}, undef)
        == 0 or croak 'matrixSslReadKeys: wrong {crt}, {key} or {pass}?';
    matrixSslNewSession($self->{_ssl}, $self->{_ssl_keys},
        undef, $SSL_FLAGS_SERVER)
        == 0 or croak 'matrixSslNewSession';
    return $self;
}

sub PREPARE {
    my ($self, $fh, $host, $port) = @_;
    if (!defined $host) {   # ... else timer will be set on CONNECTED
        $self->{_t} = EV::timer(TOHANDSHAKE, 0, $self->{_cb_t});
    }
    $self->{_slave}->PREPARE($fh, $host, $port);
    return;
}


1;
