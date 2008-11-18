package IO::Stream::MatrixSSL::const;

use warnings;
use strict;

use version; our $VERSION = qv('1.0.0');

# update DEPENDENCIES in POD & Makefile.PL & README

# Timeouts:
use constant TOHANDSHAKE    => 30;

# Custom errors:
use constant ETOHANDSHAKE   => 'ssl handshake timeout';


sub import {
    my $pkg = caller;
    no strict 'refs';
    for my $const (qw( TOHANDSHAKE ETOHANDSHAKE )) {
        *{"${pkg}::$const"} = \&{$const};
    }
    return;
}


1;
