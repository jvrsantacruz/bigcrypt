#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Large file encryption"""
import nacl.secret
import nacl.utils

import os
import sys
import copy
import logging
import mmap
from argparse import ArgumentParser
from pathlib import Path
from multiprocessing import Pool
from multiprocessing.pool import ThreadPool
import collections
from typing import Iterator, IO, List, Tuple, Callable, Optional

_LOGGING_FMT_ = '%(asctime)s %(levelname)-8s %(message)s'


class MemoryRegistry:
    """Global map of mmaps to avoid pickling

Threads and child processes should have the reference too.
Be sure register your maps BEFORE starting children processes.
    """
    def __init__(self, objs=None):
        self.objs = objs or {}

    def __getitem__(self, obj_id: int) -> mmap.mmap:
        return self.objs[obj_id]

    def add(self, mem: mmap.mmap) -> int:
        obj_id = id(mem)
        self.objs.setdefault(obj_id, mem)
        return obj_id


memory_registry = MemoryRegistry()


class Block:
    def __init__(self, n: int, size: int, block_size: int, data: bytes):
        self.n = n
        self.size = size
        self.block_size = block_size
        self.data = data

    def __repr__(self):
        return f'{type(self).__name__}(n={self.n},size={self.size})'


class MemoryBlock(Block):
    pass


class MappedBlock(Block):
    def __init__(
        self,
        n: int,
        size: int,
        block_size: int,
        mem = mmap.mmap,
        data: bytes=b'',
    ):
        self.n = n
        self.size = size
        self.block_size = block_size
        self._offset = n * block_size
        # Use a ref to the mmap to make it picklable
        self._mem_id = memory_registry.add(mem)
        # Write data to the mmap if needed
        if data:
            self.data = data

    @property
    def _mem(self) -> Block:
        return memory_registry[self._mem_id]

    @property
    def data(self) -> bytes:
        return self._mem[self._offset:self._offset + self.size]

    @data.setter
    def data(self, data: bytes) -> bytes:
        self._mem[self._offset:self._offset + self.size] = data


class Chunker:
    def __init__(self, block_size: int):
        self.block_size = block_size

    def __call__(self, stream) -> Iterator[Block]:
        pass


class StreamChunker(Chunker):
    def __call__(self, stream: IO[bytes]) -> Iterator[MemoryBlock]:
        n = 0
        data = stream.read(self.block_size)
        while data:
            yield MemoryBlock(
                n=n, size=len(data), block_size=self.block_size, data=data
            )
            data = stream.read(self.block_size)
            n += 1


class MappedChunker(Chunker):
    def __call__(self, stream: IO[bytes]) -> Iterator[MappedBlock]:
        fileno = stream.fileno()
        mem = mmap.mmap(fileno, 0, mmap.MAP_SHARED, mmap.PROT_READ)
        mem_id = memory_registry.add(mem)
        return self.iter_blocks(
            mem_id=mem_id,
            total_size=os.fstat(fileno).st_size,
        )

    def iter_blocks(self, mem_id: int, total_size: int):
        mem = memory_registry[mem_id]
        for n, size in self.calculate_blocks(total_size):
            yield MappedBlock(
                n=n,
                size=size,
                block_size=self.block_size,
                mem=mem,
            )

    def calculate_blocks(self, total_size: int) -> Iterator[Tuple[int, int]]:
        n = 0
        whole_blocks = total_size // self.block_size
        for n in range(whole_blocks):
            yield n, self.block_size

        last_block_size = total_size % self.block_size
        if last_block_size:
            n = n + 1 if n else 0
            yield n, last_block_size


class Nonce:
    def __init__(self, nonce=None, size=None):
        self.size = size or \
            (nonce and len(nonce)) or \
            nacl.secret.SecretBox.NONCE_SIZE
        self.value = nonce or nacl.utils.random(self.size)
        self._number = int.from_bytes(self.value, sys.byteorder)

    def next(self, n: int) -> bytes:
        return (self._number + n).to_bytes(self.size, sys.byteorder)


class Cipher:
    def __init__(self, key=None):
        self.key = key or nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        self.box = nacl.secret.SecretBox(self.key)
        self.tag_size = self.box.MACBYTES

    def encrypt(self, message: bytes, nonce: bytes) -> bytes:
        return self.box.encrypt(message, nonce)

    def decrypt(self, message: bytes):
        return self.box.decrypt(message)


class BlockCipher:
    def __init__(self, cipher: Cipher, nonce: Nonce):
        self.cipher = cipher
        self.nonce = nonce
        self.block_overhead = cipher.tag_size + nonce.size

    def encrypt(self, block: Block) -> Block:
        encrypted = self.cipher.encrypt(
            block.data,
            nonce=self.nonce.next(block.n)
        )
        return Block(
            n=block.n,
            size=len(encrypted),
            block_size=block.block_size + self.block_overhead,
            data=encrypted,
        )

    def decrypt(self, block: Block) -> Block:
        decrypted = self.cipher.decrypt(block.data)
        return Block(
            n=block.n,
            size=len(decrypted),
            block_size=block.block_size - self.block_overhead,
            data=decrypted,
        )


Action = Callable[[Block], Optional[Block]]


class Actions:
    def __init__(self, actions: List[Action]):
        self.actions = actions

    def __call__(self, block: Block) -> Optional[Block]:
        for action in self.actions:
            block = action(block)
        return block


class BlockProcessor:
    def __init__(self, actions: Actions):
        self.actions = actions

    def __call__(self, blocks: Iterator[Block]) -> Iterator[Optional[Block]]:
        return (self.actions(block) for block in blocks)


class ProcessBlockProcessor(BlockProcessor):
    def __init__(self, actions: Actions, pool: Pool=None):
        super().__init__(actions)
        self.pool = pool or Pool(10)

    def __call__(self, blocks: Iterator[Block]) -> Iterator[Optional[Block]]:
        return self.pool.imap_unordered(self.actions, blocks)


class ThreadBlockProcessor(BlockProcessor):
    def __init__(self, actions: Actions, pool: ThreadPool=None):
        super().__init__(actions)
        self.pool = pool or Pool(10)

    def __call__(self, blocks: Iterator[Block]) -> Iterator[Optional[Block]]:
        return self.pool.imap_unordered(self.actions, blocks)


class Writer:
    def __call__(self, block: Block) -> Block:
        pass

    def map(self, blocks: Iterator[Block]) -> Iterator[Block]:
        return map(self, blocks)


class FileWriter(Writer):
    def __init__(self, path: Path):
        self.path = path

    def __call__(self, block: Block) -> Block:
        with self.path.open('rb+') as stream:
            stream.seek(block.n * block.block_size)
            stream.write(block.data)
        return block


class MappedWriter(Writer):
    def __init__(self, stream: IO[bytes]):
        fileno = stream.fileno()
        total_size = os.fstat(fileno).st_size
        self.mem_id = memory_registry.add(
            mmap.mmap(fileno, total_size, mmap.MAP_SHARED, mmap.PROT_WRITE)
        )

    def __call__(self, block: Block) -> MappedBlock:
        return MappedBlock(
            n=block.n,
            size=block.size,
            block_size=block.block_size,
            data=block.data,
            mem=memory_registry[self.mem_id],
        )


class MappedAnonWriter(MappedWriter):
    def __init__(self, total_size: int):
        self.mem = mmap.mmap(
            -1, total_size, mmap.SHARED, mmap.PROT_READ | mmap.PROT_WRITE
        )


def printer(block: Block) -> Block:
    print(block)
    return block


def consume(iterable):
    collections.deque(iterable, maxlen=0)


class Source:
    default_block_size = 64 * 2**20

    def stream(self, *args, **kwargs) -> IO[bytes]:
        pass

    @property
    def block_size(self):
        return self.default_block_size


class FileSource(Source):
    def __init__(self, path: Path):
        self.path = path

    @property
    def size(self) -> int:
        return self.path.stat().st_size

    @property
    def total_blocks(self) -> int:
        return self.size // self.block_size + \
            int(self.size % self.block_size != 0)


class EncryptedSource(Source):
    def __init__(self, source: Source, cipher: Cipher):
        self.source = source
        self.cipher = cipher

    @property
    def size(self) -> int:
        return self.source.size \
            + self.cipher.block_overhead * self.total_blocks

    @property
    def block_size(self) -> int:
        return self.source.block_size + self.cipher.block_overhead

    @property
    def total_blocks(self) -> int:
        return self.source.total_blocks


class State:
    def __init__(
        self,
        key: Optional[bytes]=None,
        nonce: Optional[bytes]=None,
        block_size: Optional[int]=None,
        pool_size: Optional[int]=None,
    ):
        self.bytes_cipher = Cipher(key)
        self.nonce = Nonce(nonce)
        self.block_size = block_size or (64 * 2**20)
        self.pool_size = pool_size or 10
        self.cipher = BlockCipher(self.bytes_cipher, self.nonce)
        self.plain_block_size = self.block_size
        self.cipher_block_size = \
            self.block_size + self.cipher.block_overhead

    def total_cipher_size(self, plain_size: int) -> int:
        overhead = self.total_overhead(plain_size, self.plain_block_size)
        return plain_size + overhead

    def total_plain_size(self, cipher_size: int) -> int:
        overhead = self.total_overhead(cipher_size, self.cipher_block_size)
        return cipher_size - overhead

    def total_overhead(self, total_size: int, block_size: int) -> int:
        total_blocks = self.total_blocks(total_size, block_size)
        block_overhead = self.cipher.block_overhead
        return  total_blocks * block_overhead

    def total_blocks(self, total_size: int, block_size: int) -> int:
        return total_size // block_size + \
            int(total_size % block_size != 0)


def encrypt_file(source: Path, dest: Path, state: State):
    chunker = MappedChunker(state.plain_block_size)

    with source.open('rb') as source_stream:
        blocks = chunker(source_stream)

        with dest.open('wb+') as dest_stream:
            import fallocate
            fallocate.fallocate(
                dest_stream.fileno(),
                0,
                state.total_cipher_size(source.stat().st_size)
            )
            writer = MappedWriter(dest_stream)
            encrypter = ProcessBlockProcessor(Actions([
                state.cipher.encrypt,
                writer,
            ]))
            blocks = encrypter(blocks)
            blocks = map(printer, blocks)
            consume(blocks)


def decrypt_file(source: Path, dest: Path, state: State):
    chunker = MappedChunker(state.cipher_block_size)
    with source.open('rb') as source_stream:
        blocks = chunker(source_stream)

        with dest.open('wb+') as dest_stream:
            import fallocate
            fallocate.fallocate(
                dest_stream.fileno(),
                0,
                state.total_plain_size(source.stat().st_size)
            )
            writer = MappedWriter(dest_stream)
            decrypter = ProcessBlockProcessor(Actions([
                state.cipher.decrypt, writer
            ]))

            blocks = decrypter(blocks)
            blocks = map(printer, blocks)
            consume(blocks)


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
