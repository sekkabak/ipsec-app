import asyncio
import logging
import ike.IKEService


def main(localaddress, peer):
    port = 500
    loop = asyncio.get_event_loop()
    t = asyncio.Task(loop.create_datagram_endpoint(lambda: ike.IKEService.IKEService(
        (localaddress, port), (peer, port)), remote_addr=(peer, port), local_addr=(localaddress, port)))
    loop.run_until_complete(t)
    loop.run_forever()


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.DEBUG, format='%(levelname)s:%(name)s.%(funcName)s:[%(lineno)s]: %(message)s')
    logger = logging.getLogger('MAIN')
    logger.info("Starting...")
    main("127.0.0.10", "127.0.0.11")
