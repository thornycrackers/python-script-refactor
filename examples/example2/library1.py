import logging
import sys

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logger = logging.getLogger(__name__)


def foo():
    logger.debug("Library1")

if __name__ == "__main__":
    foo()
