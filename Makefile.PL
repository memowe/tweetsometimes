use strict;
use warnings;

use ExtUtils::MakeMaker;

WriteMakefile(
    VERSION     => '0.01',
    PREREQ_PM   => {
        'Mojolicious'           => '4.0',
        'Net::Twitter::Lite'    => '0.12',
    },
);
