#!/usr/bin/perl
# perl version of splitmbox.py
# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2022 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
#
# I didn't want to deal with the python2->3 transition so I rewrote it in perl...

use Mail::Mbox::MessageParser;

my ($mbox_file, $directory) = @ARGV;

if ((not defined $mbox_file) or (not defined $directory)) {
	print "splitmbox.pl mbox directory\n";
	exit;
}

if (not -d $directory) {
	print "directory $directory does not exist!\n";
	exit;
}

my $mbox_reader = new  Mail::Mbox::MessageParser( {
		'file_name' => $mbox_file,
		'enable_cache' => 0,
	} );

die $mbox_reader unless ref $mbox_reader;

# compute number of messages in mailbox
my $count = 0;
while (!$mbox_reader->end_of_file()) {
	my $email = $mbox_reader->read_next_email();
	$count = $count + 1;
}
my $width_string = sprintf("%d", $count);
my $width = length $width_string;
print "mailbox count = $count\n";
print "string width  = $width\n";

$mbox_reader->reset();

$count = 0;
while (!$mbox_reader->end_of_file()) {
	my $filename = sprintf("%s/msg.%0*d", $directory, $width, $count);
	my $email = $mbox_reader->read_next_email();

	print "filename = $filename\n";
	open(FILE, '>', $filename) or die $!;
	print FILE $$email;
	close(FILE);
	$count = $count + 1;
}


