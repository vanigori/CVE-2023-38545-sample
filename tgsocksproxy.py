#!/usr/bin/env python3

import asyncio
import struct
import socket
import time

PORT = 1080

HIDE_ERRORS_BEFORE_AUTH = True

READ_BUF_SIZE = 4096

IPV4_ADDR_LEN = 4
IPV6_ADDR_LEN = 16

BAD_IPV4_ADDR = b"\x00\x00\x00\x00"
BAD_PORT = b"\x00\x00"

# Consts from RFC1928
SOCKS5_VERSION = b"\x05"
SUBNEGOTIATION_VERSION = b"\x01"

NO_AUTH_METHOD = b"\x00"
NO_ACCEPTABLE_METHODS = b"\xff"

STATUS_SUCCESS = b"\x00"
STATUS_FAIL = b"\x01"

CMD_CONNECT = b"\x01"

ADDR_IPV4 = b"\x01"
ADDR_DOMAINNAME = b"\x03"
ADDR_IPV6 = b"\x04"

REPLY_SUCCEEDED = b"\x00"
REPLY_GENERAL_FAILURE = b"\x01"
REPLY_NOT_ALOWED = b"\x02"
REPLY_REFUSED = b"\x05"
REPLY_CMD_NOT_SUPPORTED = b"\x07"
REPLY_ADDR_TYPE_NOT_SUPPORTED = b"\x08"

RESERVED = b"\x00"

async def initial_handshake(reader, writer):
    socks_version = await reader.readexactly(1)
    if socks_version != SOCKS5_VERSION:
        return False

    n_methods = struct.unpack("!B", await reader.readexactly(1))[0]
    if n_methods == 0:
        return False

    methods = await reader.readexactly(n_methods)

    if NO_AUTH_METHOD not in methods:
        if not HIDE_ERRORS_BEFORE_AUTH:
            writer.write(SOCKS5_VERSION + NO_ACCEPTABLE_METHODS)
            await writer.drain()
        return False

    # Mock the latency between the client and server (initial handshake latency)
    time.sleep(1)
    writer.write(SOCKS5_VERSION + NO_AUTH_METHOD)
    return True

async def handle_request(reader, writer):
    "Returns host and port to connect"

    def gen_reply(reply_code, fam=ADDR_IPV4, ip=BAD_IPV4_ADDR, port=BAD_PORT):
        return SOCKS5_VERSION + reply_code + RESERVED + fam + ip + port

    socks_version = await reader.readexactly(1)
    if socks_version != SOCKS5_VERSION:
        return None, None

    cmd = await reader.readexactly(1)
    if cmd != CMD_CONNECT:
        writer.write(gen_reply(REPLY_CMD_NOT_SUPPORTED))
        await writer.drain()
        return None, None

    reserved = await reader.readexactly(1)

    address_type = await reader.readexactly(1)

    if address_type == ADDR_IPV4:
        address = await reader.readexactly(IPV4_ADDR_LEN)
    elif address_type == ADDR_IPV6:
        address = await reader.readexactly(IPV6_ADDR_LEN)
    elif address_type == ADDR_DOMAINNAME:
        address_len = struct.unpack("!B", await reader.readexactly(1))[0]

        if address_len == 0:
            return None, None

        address = await reader.readexactly(address_len)
    else:
        writer.write(gen_reply(REPLY_ADDR_TYPE_NOT_SUPPORTED))
        await writer.drain()
        return None, None

    if address_type == ADDR_IPV4:
        address = socket.inet_ntop(socket.AF_INET, address)
    elif address_type == ADDR_IPV6:
        address = socket.inet_ntop(socket.AF_INET6, address)

    port = struct.unpack("!H", await reader.readexactly(2))[0]

    try:
        reader_tgt, writer_tgt = await asyncio.open_connection(address, port)
    except ConnectionRefusedError as E:
        writer.write(gen_reply(REPLY_REFUSED))
        await writer.drain()
        return None, None
    except OSError as E:
        writer.write(gen_reply(REPLY_GENERAL_FAILURE))
        await writer.drain()
        return None, None

    writer.write(gen_reply(REPLY_SUCCEEDED, ADDR_IPV4,
                           BAD_IPV4_ADDR, BAD_PORT))
    await writer.drain()

    return reader_tgt, writer_tgt

async def handle_client(reader, writer):
    if not await initial_handshake(reader, writer):
        writer.close()
        return

    reader_tgt, writer_tgt = await handle_request(reader, writer)
    if reader_tgt is None or writer_tgt is None:
        writer.close()
        return

    async def connect_reader_to_writer(rd, wr):
        try:
            while True:
                data = await rd.read(READ_BUF_SIZE)
                if not data:
                    wr.write_eof()
                    await wr.drain()
                    wr.close()
                    return
                else:
                    wr.write(data)
                    await wr.drain()
        except (ConnectionResetError, BrokenPipeError, OSError,
                AttributeError):
            wr.close()
    # For those reading comments: This creates the communication "bridge"
    # A malicious proxy server can print the readers/writers values to perform a MITM 
    asyncio.ensure_future(connect_reader_to_writer(reader_tgt, writer))
    asyncio.ensure_future(connect_reader_to_writer(reader, writer_tgt))

async def handle_client_wrapper(reader, writer):
    try:
        await handle_client(reader, writer)
    except (asyncio.IncompleteReadError, ConnectionResetError):
        writer.close()

async def main():
    server = await asyncio.start_server(handle_client_wrapper, "127.0.0.1", PORT)

    try:
        async with server:
            await server.serve_forever()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    asyncio.run(main())