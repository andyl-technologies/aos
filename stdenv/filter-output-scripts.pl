# Selects installed shebang files while retaining their original inodes.
# The temporary directory lives in the output to avoid cross-mount hard links.

use strict;
use warnings;
use Cwd qw(abs_path);
use File::Find;

@ARGV == 2 or die "usage: filter-output-scripts.pl OUTPUT DESTINATION\n";
my ($source, $destination) = map {
    abs_path($_) or die "cannot resolve $_: $!\n"
} @ARGV;

$source ne $destination && index("$destination/", "$source/") == 0
    or die "destination must be inside the output tree\n";

my $index = 0;
find({
    no_chdir => 1,
    wanted => sub {
        my $path = $File::Find::name;
        if ($path eq $destination) {
            $File::Find::prune = 1;
            return;
        }
        return if -l $path || !-f $path;

        open my $input, '<', $path or die "cannot open $path: $!\n";
        binmode $input;
        my $length = read($input, my $prefix, 2);
        defined $length or die "cannot read $path: $!\n";
        close $input or die "cannot close $path: $!\n";
        return unless $prefix eq '#!';

        ++$index;
        link($path, "$destination/$index")
            or die "cannot link $path: $!\n";
    },
}, $source);
