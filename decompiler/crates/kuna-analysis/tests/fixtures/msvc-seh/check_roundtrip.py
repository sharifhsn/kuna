"""Build the x64 MSVC source oracle, and optionally run its consumer on a Kuna export."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

FIXTURE = Path(__file__).resolve().parent
FUNCTIONS = ('sample_except', 'sample_finally', 'sample_nested')


def run(argv, cwd):
    subprocess.run(argv, cwd=cwd, check=True, timeout=90)


def compile_and_check(implementation, work, executable):
    run(['cl', '/nologo', '/W3', '/we4013', '/O2', '/EHa', '/TC', '/Z7',
         '/FI' + str(FIXTURE / 'helpers.h'), implementation, FIXTURE / 'helpers.c',
         FIXTURE / 'check.c', '/Fe:' + executable, '/link', '/DEBUG:FULL',
         '/INCREMENTAL:NO'], work)
    run([work / executable], work)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--kuna', type=Path, help='export the three source functions with this native CLI')
    mode.add_argument('--exported-c', type=Path, help='check an existing fixture export with its header alongside it')
    parser.add_argument('--specs', type=Path, help='processor specs directory for --kuna')
    args = parser.parse_args()
    if args.specs and not args.kuna:
        parser.error('--specs requires --kuna')
    if os.environ.get('VSCMD_ARG_TGT_ARCH') != 'x64':
        parser.error('use an x64 MSVC Developer Command Prompt')

    with TemporaryDirectory() as tmp:
        work = Path(tmp)
        print('Checking the original source', flush=True)
        compile_and_check(FIXTURE / 'scopes.c', work, 'scopes.exe')
        if not args.kuna and not args.exported_c:
            return
        if args.kuna:
            out = work / 'export'
            cmd = [args.kuna.resolve(), 'decompile-project', work / 'scopes.exe',
                   '--functions', ','.join(FUNCTIONS), '--no-asm', '-o', out]
            if args.specs:
                cmd.extend(['--sleighpath', args.specs.resolve()])
            run(cmd, work)
            implementation = out / 'scopes.exe.c'
        else:
            implementation = args.exported_c.resolve(strict=True)
        print('Checking the exported implementations', flush=True)
        compile_and_check(implementation, work, 'export-check.exe')


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        print(f"{error.cmd[0]} exited with status {error.returncode}", file=sys.stderr)
        sys.exit(error.returncode)
