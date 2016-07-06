import sys
import subprocess
import shlex
from os import path

args = sys.argv

usage = '''
    Usage: python %s -inkey [public.key] -in [signed.bin] -out [output.bin]
''' % args[0]

not_there = False
not_there_list = []

for arg in ["-inkey", "-out", "-in"]:
    if arg not in args:
        not_there = True
        not_there_list.append(arg)

if not_there:
    print 'Missing arg(s): %s.' % not_there_list
    print usage
    sys.exit(1)

inkey = args[args.index("-inkey")+1]
out = args[args.index("-out")+1]
_in = args[args.index("-in")+1]

command = "openssl rsautl -verify -pubin -inkey %s -in %s -out %s" % (inkey, _in, out)

print command
split = shlex.split(command)
call = subprocess.call(split)
sys.exit(call)