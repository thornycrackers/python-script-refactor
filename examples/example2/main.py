import logging
import sys

import library1

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Uncomment below to mute Library1's debug
# logging.getLogger("library1").setLevel(logging.INFO)
library1.foo()

logger.debug("Main File")
