package IO::Stream::MatrixSSL::Client;

use warnings;
use strict;
use Carp;

use version; our $VERSION = qv('1.0.0');    # update POD & Changes & README

# update DEPENDENCIES in POD & Makefile.PL & README
use IO::Stream::const;
use IO::Stream::MatrixSSL::const;
use Crypt::MatrixSSL 1.83;
use File::ShareDir;
use Scalar::Util qw( weaken );

use base qw( IO::Stream::MatrixSSL );

use constant trusted_CA
    => File::ShareDir::dist_file('IO-Stream-MatrixSSL', 'ca-bundle.crt');


# FIXME documentation: cb_validate->cb, default value for trusted_CA
sub new {
    my ($class, $opt) = @_;
    my $self = bless {
        trusted_CA  => trusted_CA,  # filename(s) with trusted root CA cert(s)
        cb          => undef,       # callback for validating certificate
        %{$opt},
        out_buf     => q{},                 # modified on: OUT
        out_pos     => undef,               # modified on: OUT
        out_bytes   => 0,                   # modified on: OUT
        in_buf      => q{},                 # modified on: IN
        in_bytes    => 0,                   # modified on: IN
        ip          => undef,               # modified on: RESOLVED
        is_eof      => undef,               # modified on: EOF
        _param      => [],          # param for cb
        # TODO Make this field public and add feature 'restore session'.
        _ssl_session=> undef,       # MatrixSSL 'sessionId' object
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
    matrixSslReadKeys($self->{_ssl_keys}, undef, undef, undef,
        $self->{trusted_CA})
        == 0 or croak 'matrixSslReadKeys: wrong {trusted_CA}?';
    matrixSslNewSession($self->{_ssl}, $self->{_ssl_keys},
        $self->{_ssl_session}, 0)
        == 0 or croak 'matrixSslNewSession: wrong {_ssl_session}?';
    matrixSslEncodeClientHello($self->{_ssl}, $self->{out_buf}, 0)
        == 0 or croak 'matrixSslEncodeClientHello';
    # Prepare first param for cb.
    $self->{_param}[0] = $self;
    weaken $self->{_param}[0];
    if (defined $self->{cb}) {
        matrixSslSetCertValidator($self->{_ssl}, $self->{cb}, $self->{_param});
    }
    return $self;
}

sub PREPARE {
    my ($self, $fh, $host, $port) = @_;
    if (!defined $host) {   # ... else timer will be set on CONNECTED
        $self->{_t} = EV::timer(TOHANDSHAKE, 0, $self->{_cb_t});
    }
    # Prepare second param for cb.
    my $io = $self;
    while ($io->{_master}) {
        $io = $io->{_master};
    }
    $self->{_param}[1] = $io;
    weaken $self->{_param}[1];
    $self->{_slave}->PREPARE($fh, $host, $port);
    $self->{_slave}->WRITE();                       # output 'client hello'
    return;
}


1;
