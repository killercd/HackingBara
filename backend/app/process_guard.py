"""A scanner process group must not outlive its worker, including browser grandchildren."""

import os
import signal
import subprocess
import sys
import time


def main():
    expected_parent = int(sys.argv[1])
    if os.getppid() != expected_parent:
        return 1
    child = subprocess.Popen(sys.argv[2:], stdin=subprocess.DEVNULL)
    while child.poll() is None:
        if os.getppid() != expected_parent:
            os.killpg(os.getpgrp(), signal.SIGKILL)
        time.sleep(0.1)
    if os.getppid() != expected_parent:
        os.killpg(os.getpgrp(), signal.SIGKILL)
    return child.returncode


if __name__ == "__main__":
    sys.exit(main())
