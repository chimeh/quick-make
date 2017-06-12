#!/usr/bin/env perl
# Copyright (C) 2016, SZFORWARD, huangjimin

use strict;
#use warnings;
use sort 'stable';
use File::Basename;

foreach (@ARGV) {
    my $file = $_;
    open (FH, $file);
    local $/; undef $/;
    my $line = <FH>;
    close (FH);
    my @val;
    my @prototype;
    my @ret1;
    my @ret2;
    my @funcname;
    my @args;
#    (@prototype @ret1 @ret2 @funcname @args) = $line =~ m/(^\s*(unsigned|signed)?[ \r\n]+(void|int|char|short|long|float|double)\s+(\w+)\s*\([^)]*\)\s*);/mg;
    @val  = $line =~ m/(^\s*(unsigned|signed)?[ \r\n]+(void|int|char|short|long|float|double)\s+(\w+)\s*\([^)]*\)\s*);/mg;

    foreach (@val) {
        if (m/[()]+/) {
#            print "--------------\n";
            print $_;
#            print "\n-----\n";
        }
    }
}

