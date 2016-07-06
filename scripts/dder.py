import sys
import subprocess
import shlex
from os import path

args = sys.argv

usage = '''
    Usage: python %s -in [infile.data] -out [outfile.data] -bs [bs] -h [header] -l [length] -c [count].
''' % args[0]

not_there = False
not_there_list = []

for arg in ["-in", "-out", "-bs", "-h", "-l", "-c"]:
    if arg not in args:
        not_there = True
        not_there_list.append(arg)

if not_there:
    print 'Missing arg(s): %s.' % not_there_list
    print usage
    sys.exit(1)

infile = args[args.index("-in")+1]

if not path.exists(infile):
    print "The file %s does not exist." % infile
    print usage
    sys.exit(1)

outfile = args[args.index("-out")+1]
bs = args[args.index("-bs")+1]
header = args[args.index("-h")+1]
length = args[args.index("-l")+1]
count = args[args.index("-c")+1]

command = 'dd if=%s of=%s bs=%s skip=%s count=%s' % (infile, outfile, bs, (int(header)+int(length)), count)
ret_code = subprocess.call(shlex.split(command))

sys.exit(ret_code)