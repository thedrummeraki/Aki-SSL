import sys
import subprocess
import shlex
from os import path

args = sys.argv

usage = '''
    Usage: python %s infile.data outfile.data bs header length count.

    arguments must be passed in order:
        infile.data
        outfile.data
        bs
        header
        length
        count
''' % args[0]

if len(args) < 7:
    print usage
    sys.exit(1)

infile = args[1]

if not path.exists(infile):
    print "The file %s does not exist." % infile
    print usage
    sys.exit(1)

outfile = args[2]
bs = args[3]
header = args[4]
length = args[5]
count = args[6]

command = 'dd if=%s of=%s bs=%s skip=%s count=%s' % (infile, outfile, bs, (int(header)+int(length)), count)
ret_code = subprocess.call(shlex.split(command))

sys.exit(ret_code)