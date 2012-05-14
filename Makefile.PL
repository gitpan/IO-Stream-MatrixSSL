use inc::Module::Install;

name     'IO-Stream-MatrixSSL';
all_from 'lib/IO/Stream/MatrixSSL.pm';
author   'Alex Efros <powerman-asdf@ya.ru>';
license  'perl';

requires	'version';
requires	'IO::Stream';
requires	'Crypt::MatrixSSL'     => '1.83';
requires	'File::ShareDir';

test_requires	'Test::More';
test_requires	'Test::Exception';
test_requires	'EV';

recommends      'Test::CheckManifest'   => '0.9';
recommends      'Test::Perl::Critic';
recommends      'Test::Pod::Coverage'   => '1.08';
recommends      'Pod::Coverage'         => '0.18';
recommends      'Test::Pod'             => '1.22';

install_share;

open my $f, '>', 't/config.pm' or die "open: $!";
my $online = prompt 'Run tests which require internet connection', 'n';
$online = lc $online eq 'y' ? 'y' : 'n';
printf {$f} "use constant CFG_ONLINE => '%s';\n", $online;
printf {$f} '1;';
close $f or die "close: $!";

auto_install;

WriteAll;

