import sys
import time
import argparse
import struct
import hashlib
import datetime
import os
import logging
import errno

import stem
import stem.control

handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(fmt="%(asctime)s [%(levelname)s]: %(message)s"))

logger = logging.getLogger("onion-load-balancer")
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)


def hs_desc_handler(event):
    if event.type == "HS_DESC":
        logger.info("HS_DESC received")
        if event.reason:
            logger.info("Descriptor fetching from {} for HS {} failed with error: {}".format(event.directory_fingerprint, event.address, event.reason))
        else:
            logger.info("Descriptor contains:\n\tAdress: {}\n\tAuthentication: {}\n\tDirectory: {}\n\tDescriptor_id: {}".format(event.address, event.authentication, event.directory, event.descriptor_id))

    if event.type == "HS_DESC_CONTENT":
        logger.info("HS_DESC_CONTENT received")
        # Save the descriptor content to disk
        descriptor_text = str(event.descriptor).encode('utf-8')

        # Make sure the descriptor is not empty
        if len(descriptor_text) < 5:
            logger.debug("Empty descriptor received for %s" % event.address)
            return
        else:
            parsed_descriptor = stem.descriptor.hidden_service_descriptor.HiddenServiceDescriptor(descriptor_text, validate=True)
            introduction_points = parsed_descriptor.introduction_points()
            logger.info("Descriptor contains:\n\tAdress: {}\n\tAuthentication: {}\n\tDirectory: {}\n\tDescriptor_id: {}\n\tIntroduction_Points: {}".format(event.address, event.authentication, event.directory, event.descriptor_id, introduction_points))



def main():
    with stem.control.Controller.from_port(port=9051) as controller:
        # Create a connection to the Tor control port
        try:
            controller.authenticate()
        except stem.connection.AuthenticationFailure as exc:
            logger.error("Unable to authenticate to Tor control port: %s" % exc)
            sys.exit(1)
        else:
            controller.set_caching(False)
            logger.debug("Successfully connected to the Tor control port")

        # Add event listeners for HS_DESC and HS_DESC_CONTENT
        controller.add_event_listener(hs_desc_handler, stem.control.EventType.HS_DESC)
        controller.add_event_listener(hs_desc_handler, stem.control.EventType.HS_DESC_CONTENT)

    try:
        while True:
            continue
    except KeyboardInterrupt:
        logger.info("Stopping descriptor fetching")
        sys.exit(0)

if __name__ == '__main__':
    main()
