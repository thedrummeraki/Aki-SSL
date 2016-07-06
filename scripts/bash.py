import sys
import subprocess
import shlex

args = sys.argv

if len(args) < 2:
    sys.exit(0)

commands = args[1]
commands = shlex.split(commands)

code = subprocess.call(commands)

sys.exit(code)