#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Large file encryption"""
import nacl.secret
import nacl.utils

import sys
import logging
from argparse import ArgumentParser
from pathlib import Path
from multiprocessing import Pool
#from multiprocessing.pool import ThreadPool as Pool

_LOGGING_FMT_ = '%(asctime)s %(levelname)-8s %(message)s'


class Block:
    def __init__(self, n: int, size: int, max_size: int, data: bytes):
        self.n = n
        self.size = size
        self.max_size = max_size
        self.data = data

    def __repr__(self):
        return f'Block(n={self.n},size={self.size})'


class Chunker:
    def __init__(self, max_size: int = 64 * 2**20):
        self.max_size = max_size

    def __call__(self, stream):
        n = 0
        data = stream.read(self.max_size)
        while data:
            yield Block(n=n, size=len(data), max_size=self.max_size, data=data)
            data = stream.read(self.max_size)
            n += 1


class State:
    def __init__(self, key=None, nonce=None):
        self.key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        self.nonce = nonce or \
            nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        self.box = nacl.secret.SecretBox(self.key)
        self.nonce_size = self.box.NONCE_SIZE
        self.extra_size = self.box.NONCE_SIZE + self.box.MACBYTES
        self._nonce_int = int.from_bytes(self.nonce, sys.byteorder)

    def encrypt(self, block: Block) -> Block:
        encrypted = self.encrypt_bytes(block.data, self.next_nonce(block.n))
        return Block(
            n=block.n,
            size=len(encrypted),
            max_size=block.max_size + self.extra_size,
            data=encrypted
        )

    def encrypt_bytes(self, message: bytes, nonce: bytes) -> bytes:
        return self.box.encrypt(message, nonce)

    def encrypt_stream(self, stream, chunker=Chunker()):
        return Pool(5).imap_unordered(self.encrypt, chunker(stream))

    def next_nonce(self, n: int) -> bytes:
        return (self._nonce_int + n).to_bytes(self.nonce_size, sys.byteorder)

    def decrypt(self, block: Block) -> Block:
        decrypted = self.decrypt_bytes(block.data)
        return Block(
            n=block.n,
            size=len(decrypted),
            max_size=block.max_size - self.extra_size,
            data=decrypted,
        )

    def decrypt_bytes(self, message: bytes):
        return self.box.decrypt(message)

    def decrypt_stream(self, stream, chunker=Chunker()):
        chunker = Chunker(chunker.max_size + self.extra_size)
        return Pool(5).imap_unordered(self.decrypt, chunker(stream))


def encrypt_file(source: Path, dest: Path, state: State):
    with source.open('rb') as source_stream:
        with dest.open('wb') as dest_stream:
            write_blocks(state.encrypt_stream(source_stream), dest_stream)


def decrypt_file(source: Path, dest: Path, state: State):
    with source.open('rb') as source_stream:
        with dest.open('wb') as dest_stream:
            write_blocks(state.decrypt_stream(source_stream), dest_stream)


def write_blocks(blocks, stream):
    for block in blocks:
        stream.seek(block.n * block.max_size)
        stream.write(block.data)


def error(msg, is_exit=True):
    logging.error(msg)
    if is_exit:
        sys.exit()


def parse_args():
    """Parses the command line and checks some values.
    Returns parsed options and positional arguments: (opts, args)"
    """
    parser = ArgumentParser(usage="%(prog)s [options] ARG ARG")

    parser.add_argument("--encrypt", action="store_true")
    parser.add_argument("source", type=Path)
    parser.add_argument("dest", type=Path)
    parser.add_argument("clear", type=Path)

    parser.add_argument("-v", "--verbose", dest="verbose", action="count",
                        default=0, help="")

    args = parser.parse_args()

    # Configure logging
    logging_levels = {0: logging.WARNING, 1: logging.INFO, 2: logging.DEBUG}
    level = logging_levels[args.verbose if args.verbose < 3 else 2]
    logging.basicConfig(level=level, format=_LOGGING_FMT_)

    return args


def main():
    args = parse_args()
    state = State()
    encrypt_file(args.source, args.dest, state)
    decrypt_file(args.dest, args.clear, state)

if __name__ == "__main__":
    main()
