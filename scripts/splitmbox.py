#! /usr/bin/env python3
""" Split a Unix-style mailbox into individual files

Written by Aquarius <aquarius@kryogenix.org>
Usage: splitmbox.py <mailbox-file> <directory>

This will create files numbered 01,02,03... in <directory>. The
number of prefixed zeroes will make all filenames in the
directory the same length. """

import mailbox,sys,getopt,string,os,subprocess

VERSION = '0.1'
USAGE = """Usage: splitmbox.py [ OPTION ] <mailbox-file> <directory>

   -h, --help
            Show this help text and exit
   -v, --version
            Show file version and exit

This will create files numbered 01,02,03... in <directory>. The
number of prefixed zeroes will make all filenames in the
directory the same length. """


try:
	optlist, args = getopt.getopt(sys.argv[1:],'hv',['help','version'])
except getopt.error, error_text:
	print error_text,'\n'
	print USAGE
	sys.exit(1)

for tuple in optlist:
	if tuple[0] == '-h' or tuple[0] == '--help':
		print USAGE
		sys.exit(0)
	if tuple[0] == '-v' or tuple[0] == '--version':
		print VERSION
		sys.exit(0)

if len(args) != 2:
	print USAGE

mbox_fname, output_dir = args
if output_dir[-1] != '/':
	output_dir = output_dir + '/'

# Make the output directory, if required
try:
	os.mkdir(output_dir)
except os.error,ertxt:
	if string.find(str(ertxt),'File exists') == -1:
		print 'Failed to create or use directory',output_dir,'[',ertxt,']'
		sys.exit(1)

try:
	mbox_file = open(mbox_fname)
except:
	print "Failed to open file",mbox_fname
	sys.exit(1)

mbox = mailbox.UnixMailbox(mbox_file)

# Find out how many messages in the mailbox
count = 0
while 1:
	msg = mbox.next()
	if not msg:
		break
	count = count + 1

# Now do it again, outputting files

mbox_file.close()
mbox_file = open(mbox_fname)
mbox = mailbox.UnixMailbox(mbox_file)

digits = len(str(count))
#digits = 3
count = 0
while 1:
	msg = mbox.next()
	if not msg:
		break
	fname = output_dir+'msg.'+('0'*digits+str(count))[-digits:]
	print 'Writing ', fname
	outfile = open(fname,'w')
	outfile.write('From foo@baz ');
	outfile.write(subprocess.check_output('date'));
	for s in msg.headers:
		outfile.write(s)
	outfile.write('\n')
	for s in msg.fp.readlines():
		outfile.write(s)
	outfile.close()
	count = count + 1
