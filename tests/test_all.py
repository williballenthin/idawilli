import os
import logging

import idc
import idaapi
import pytest

import idawilli


logger = logging.getLogger(__name__)


def main():
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger().setLevel(logging.DEBUG)

    pytest.main(['--capture=sys', os.path.dirname(__file__)])


if __name__ == '__main__':
    main()
