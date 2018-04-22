use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'App::DHCPClientUtils',
    AUTHOR           => q{Jari Turkia <jatu@hqcodeshop.fi>},
    VERSION_FROM     => 'lib/App/DHCPClientUtils.pm',
    ABSTRACT_FROM    => 'lib/App/DHCPClientUtils.pm',
    LICENSE          => 'artistic_2',
    PL_FILES         => {},
    MIN_PERL_VERSION => '5.006',
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => '0',
    },
    BUILD_REQUIRES => {
        'Test::More' => '0',
    },
    PREREQ_PM => {
        'Net::Interface'   => '1.012',
        'Net::IP'          => '1.26',
        'Net::ISC::DHCPClient' => '0.02',
        'Template'         => '2.20',
        'Getopt::Long'     => '2.40',
    },
	"EXE_FILES" => [
		"bin/network-interface-info.pl",
		"bin/multi-homed-routing.pl"
	],
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'App-DHCPClientUtils-*' },
);
