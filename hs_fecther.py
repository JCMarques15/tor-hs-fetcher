import logging

import stem
import stem.control
import schedule


handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(fmt="%(asctime)s [%(levelname)s]: "
                                           "%(message)s"))

logger = logging.getLogger("onion-load-balancer")
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)


def hs_desc_handler(event):
  if event.type == "HS_DESC":
    logger.info("")
    if event.reason:
      logger.info("Descriptor fetching from {} for HS {} failed "
                  "with error: {}".format(event.directory_fingerprint, event.address, event.reason))
    else:
      logger.info("Received 
