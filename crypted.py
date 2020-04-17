#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Large file encryption"""
import nacl.secret
import nacl.utils
from cached_property import cached_property

import os
import io
import sys
import copy
import logging
import mmap
import hashlib
from enum import Enum
from heapq import heappush, heappop
from argparse import ArgumentParser
from pathlib import Path
from multiprocessing import Pool
from multiprocessing.pool import ThreadPool
import fallocate
import collections
from typing import Iterator, IO, List, Tuple, Callable, Optional, Any

_LOGGING_FMT_ = '%(asctime)s %(levelname)-8s %(message)s'


class MemoryRegistry:
    """Global registry of maps to avoid pickling objects

The mmap objects are not pickable and thus usable in queues.
Threads and child processes should have the reference too.
Be sure to register your maps BEFORE starting child processes.
    """
    def __init__(self, objs=None):
        self.objs = objs or {}

    def __getitem__(self, obj_id: int) -> mmap.mmap:
        return self.objs[obj_id]

    def add(self, mem: mmap.mmap) -> int:
        obj_id = id(mem)
        self.objs.setdefault(obj_id, mem)
        return obj_id

    def __repr__(self) -> str:
        return f'MemoryRegistry(objs={set(self.objs)})'


memory_registry = MemoryRegistry()


class Block:
    """Basic encryption unit"""

    def __init__(self, n: int, size: int, block_size: int, data: bytes):
        self.n = n
        self.size = size
        self.block_size = block_size
        self.data = data

    def __lt__(self, other: 'Block') -> bool:
        return self.n < other.n

    def __repr__(self):
        return f'{type(self).__name__}(n={self.n},size={self.size})'


class MemoryBlock(Block):
    """Block that keeps the data in memory"""


class MappedBlock(Block):
    """Memory mapped block

The contents of the block are stored in an open mmap.
This requires the file to exist and to be exactly the right size.
The memory registry is used to make instances picklable.
    """
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
    def _mem(self) -> mmap.mmap:
        return memory_registry[self._mem_id]

    @property
    def data(self) -> bytes:
        return self._mem[self._offset:self._offset + self.size]

    @data.setter
    def data(self, data: bytes) -> bytes:
        self._mem[self._offset:self._offset + self.size] = data


class Storage:
    """Data storage representation

It abstracts the different possible data devices.

This should always be able to open a byte stream from the underlaying resource.
Total size might not be available for pipes and streams.
The max_blocks represents possible limitations in the amount of blocks that can
be processed.
    """
    max_blocks = None

    def stream(self, *args, **kwargs) -> IO[bytes]:
        raise NotImplementedError()

    @property
    def size(self) -> Optional[int]:
        return None

    def __repr__(self):
        return f'{type(self).__name__}()'


class S3Storage(Storage):
    """Represents an existing S3 file"""
    max_blocks = 10000


class FileStorage(Storage):
    """Represents a file in the filesystem"""

    def __init__(self, path: Path):
        self.path = path

    def stream(self, *args, **kwargs) -> IO[bytes]:
        return self.path.open(*args, **kwargs)

    @property
    def size(self) -> int:
        return self.path.stat().st_size

    def __repr__(self):
        return f'{type(self).__name__}(path={self.path})'


class StreamStorage(Storage):
    """Represents an existing open file"""

    def __init__(self, stream: IO[bytes]):
        self._stream = stream

    def stream(self) -> IO[bytes]:
        return self._stream


class Reader:
    """Create blocks from a given stream"""

    def __init__(self, block_size: int):
        self.block_size = block_size

    def iter_storage(self, storage: Storage) -> Iterator[Block]:
        raise NotImplementedError()

    def __call__(self, stream: IO[bytes]) -> Iterator[Block]:
        raise NotImplementedError()

    def __repr__(self):
        return f'{type(self).__name__}(block_size={self.block_size})'


class StreamReader(Reader):
    """Create blocks from a file handler"""

    def iter_storage(self, storage: StreamStorage) -> Iterator[MemoryBlock]:
        yield from self(storage.stream())

    def __call__(self, stream: IO[bytes]) -> Iterator[MemoryBlock]:
        n = 0
        data = stream.read(self.block_size)
        while data:
            yield MemoryBlock(
                n=n, size=len(data), block_size=self.block_size, data=data
            )
            data = stream.read(self.block_size)
            n += 1


class MappedReader(Reader):
    """Create memory mapped blocks from a file handler

This requires the file to exist in the filesystem and to know it's full size.
A mmap is created for the file and registered at the MemoryRegistry.
    """
    def iter_storage(self, storage: FileStorage) -> Iterator[MappedBlock]:
        with storage.stream('rb+') as stream:
            yield from self(stream)

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

    def __repr__(self):
        return f'type(self).__name__('\
            'block_size={self.block_size},mem={self.mem_id})'


class Nonce:
    """Representation of a cryptographic nonce"""

    def __init__(self, nonce=None, size=None):
        self.size = size or \
            (nonce and len(nonce)) or \
            nacl.secret.SecretBox.NONCE_SIZE
        self.value = nonce or nacl.utils.random(self.size)
        self._number = int.from_bytes(self.value, sys.byteorder)

    def next(self, n: int) -> bytes:
        """Generate a unique number for every presented block"""
        return (self._number + n).to_bytes(self.size, sys.byteorder)


class Cipher:
    """Cyptographic functions to encrypt and decrypt bytes"""

    def __init__(self, key=None):
        self.key = key or nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        self.box = nacl.secret.SecretBox(self.key)
        self.tag_size = self.box.MACBYTES

    def encrypt(self, message: bytes, nonce: bytes) -> bytes:
        return self.box.encrypt(message, nonce)

    def decrypt(self, message: bytes):
        return self.box.decrypt(message)

    def __repr__(self):
        return f'Cipher()'


class BlockCipher:
    """Adapter to encrypt data in blocks"""

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

    def __repr__(self):
        return f'BlockCipher(cipher={self.cipher})'


Action = Callable[[Block], Optional[Block]]


class Actions:
    """Collection of callables"""

    def __init__(self, actions: List[Action]):
        self.actions = actions

    def __call__(self, block: Block) -> Optional[Block]:
        for action in self.actions:
            block = action(block)
        return block


class BlockProcessor:
    """Process blocks by applying a set of actions"""
    def __init__(self, actions: Actions):
        self.actions = actions

    def __call__(self, blocks: Iterator[Block]) -> Iterator[Optional[Block]]:
        raise NotImplementedError()


class SequentialBlockProcessor(BlockProcessor):
    """Process blocks one after another"""

    def __call__(self, blocks: Iterator[Block]) -> Iterator[Optional[Block]]:
        return (self.actions(block) for block in blocks)


class ProcessBlockProcessor(BlockProcessor):
    """Process blocks using a pool of processes"""

    def __init__(self, actions: Actions, pool: Pool=None):
        super().__init__(actions)
        self.pool = pool or Pool(10)

    def __call__(self, blocks: Iterator[Block]) -> Iterator[Optional[Block]]:
        return self.pool.imap_unordered(self.actions, blocks)


class ThreadBlockProcessor(BlockProcessor):
    """Process blocks using a pool of threads"""

    def __init__(self, actions: Actions, pool: ThreadPool=None):
        super().__init__(actions)
        self.pool = pool or Pool(10)

    def __call__(self, blocks: Iterator[Block]) -> Iterator[Optional[Block]]:
        return self.pool.imap_unordered(self.actions, blocks)


class Writer:
    """Write a single block into an storage"""

    def __call__(self, block: Block) -> Block:
        raise NotImplementedError()

    def map(self, blocks: Iterator[Block]) -> Iterator[Block]:
        return map(self, blocks)


class FileWriter(Writer):
    """Write a single block into a given file

It stores the path instead of the file handler to avoid problems while
writing in child processes.
    """
    @property
    def from_storage(cls, storage: FileStorage) -> Writer:
        return cls(storage.path)

    def __init__(self, path: Path):
        self.path = path

    def __call__(self, block: Block) -> Block:
        with self.path.open('wb') as stream:
            return self._write(block, stream)

    def map(self, blocks: Iterator[Block]) -> Iterator[Block]:
        with self.path.open('wb') as stream:
            for block in blocks:
                yield self._write(block, stream)

    def _write(self, block: Block, stream: IO[bytes]) -> Block:
        stream.seek(block.n * block.block_size)
        stream.write(block.data)
        return block


class StreamWriter(Writer):
    """Write blocks into a stream, in order"""
    def __init__(self, stream: IO[bytes]):
        self._stream = stream

    def map(self, blocks: Iterator[Block]) -> Iterator[Block]:
        return (
            self._stream.write(block.data)
            for block in self._blocks_in_order(blocks)
        )

    def _blocks_in_order(self, blocks: Iterator[Block]) -> Iterator[Block]:
        """Sort the blocks as they come

It will keep a buffer of blocks if they don't come in order.
Worst case is that they come in reverse order, all blocks being queued.
        """
        n = 0
        heap = []
        for block in blocks:
            heappush(heap, block)
            while heap and heap[0].n == n:
                n += 1
                yield heappop(heap)


class MappedWriter(Writer):
    """Memory mapped writer

It writes the block into an existing file via memory map.
The total size must be known and the file should be already of the target size.
    """
    def __init__(self, stream: IO[bytes], total_size: int):
        fileno = stream.fileno()
        # Make sure the target file is of the right size without
        # taking up the space, the file it's just a big "hole"
        fallocate.fallocate(fileno, 0, total_size)
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


class MappedAnonWriter(Writer):
    """Memory mapped writer into memory

It saves the block into an anonymous memory region.
Total size must be known, but the file is not persisted.
This is useful to pass the memory among processes.
    """

    def __init__(self, total_size: int):
        mem = mmap.mmap(
            -1, total_size, mmap.SHARED, mmap.PROT_READ | mmap.PROT_WRITE
        )
        self.mem_id = memory_registry.add(mem)


def printer(block: Block) -> Block:
    """Action of printing a single block for debug"""
    print(block)
    return block


def consume(iterable):
    """Efficiently iterate over a sequence discarding the results"""
    collections.deque(iterable, maxlen=0)


class Source:
    """Represents an encrypted data source or destination

It's a wrapper over Storage objects that own the data
but adding the needed features for encryption and decryption.

As with the Storage, the size might not be available.
    """
    default_block_size = 64 * 2**20 # 64 MiB

    def __init__(self, storage: Storage, cipher: Cipher):
        self.storage = storage
        self.cipher = cipher

    def stream(self, *args, **kwargs):
        return self.storage.stream(*args, **kwargs)

    @property
    def block_size(self) -> int:
        raise NotImplementedError()

    @property
    def size(self) -> Optional[int]:
        raise NotImplementedError()

    @cached_property
    def total_blocks(self) -> Optional[int]:
        if self.size is not None:
            return self.size // self.block_size +\
                0 if self.size % self.block_size == 0 else 1

    @cached_property
    def total_overhead(self) -> Optional[int]:
        if self.total_blocks is not None:
            return self.total_blocks * self.cipher.block_overhead

    def __repr__(self):
        return f'{type(self).__name__}({self.storage},{self.cipher})'


class EncryptedSource(Source):
    """Represents an encrypted data source

It is assumed that the contents of the storage are encrypted using cipher.
    """
    def __init__(
        self,
        storage: Storage,
        cipher: Cipher,
        origin: 'DecryptedSource'=None
    ):
        super().__init__(storage, cipher)
        self.origin = origin

    @cached_property
    def block_size(self) -> int:
        # Use the "round" default block size for the encrypted file
        # Optimize io block size for the encrypted version
        if not self.origin:
            return self.default_block_size

        # Take the plain block size and add the encrypting overhead
        # This overhead is due to the validation tag and the nonce
        return self.origin.block_size + self.cipher.block_overhead

    @cached_property
    def size(self) -> Optional[int]:
        if not self.origin:
            return self.storage.size

        # Calculate the encrypted total size by adding the accumulated overhead
        # to the size of the plain version of the data
        if self.origin.size is not None:
            return self.origin.size + \
                self.origin.total_blocks * self.origin.total_overhead


class DecryptedSource(Source):
    """Represents the plain version of the data source

It calculates the sizes for using cipher to encrypt it.
    """
    def __init__(
        self,
        storage: Storage,
        cipher: Cipher,
        origin: EncryptedSource=None
    ):
        super().__init__(storage, cipher)
        self.origin = origin

    @cached_property
    def block_size(self) -> int:
        base_size = self.default_block_size
        if self.origin:
            base_size = self.origin.block_size

        # Plain size is "not round" as it expressed as
        # the encrypted block without the cipher overhead.
        return base_size - self.cipher.block_overhead

    @cached_property
    def size(self) -> Optional[int]:
        if not self.origin:
            return self.storage.size

        # The total size of the plain data is the encrypted size
        # without the accumulated cipher overhead
        if self.origin.size is not None:
            return self.origin.size -\
                self.origin.total_blocks * self.cipher.block_overhead


class Mode(Enum):
    ENCRYPT = 1
    DECRYPT = 2

    def __str__(self):
        return 'Encrypt' if self == Mode.ENCRYPT else 'Decrypt'


class Context:
    """Encryption context holds together everything needef for the process"""

    def __init__(
        self,
        mode: Mode,
        cipher: Cipher,
        origin: Storage,
        target: Storage,
    ):
        self.mode = mode
        self.cipher = cipher
        self.origin_storage = origin
        self.target_storage = target

    @cached_property
    def origin(self) -> Source:
        if self.mode == Mode.ENCRYPT:
            return DecryptedSource(self.origin_storage, self.cipher)
        return EncryptedSource(self.origin_storage, self.cipher)

    @cached_property
    def target(self) -> Source:
        if self.mode == Mode.ENCRYPT:
            return EncryptedSource(
                self.target_storage, self.cipher, origin=self.origin
            )
        return DecryptedSource(
            self.target_storage, self.cipher, origin=self.origin
        )

    @property
    def reader(self) -> Reader:
        storage = self.origin.storage
        block_size = self.origin.block_size

        if isinstance(storage, StreamStorage):
            return StreamReader(block_size)
        elif isinstance(storage, FileStorage):
            return MappedReader(block_size)
        else:
            raise NotImplementedError()

    @cached_property
    def crypt(self):
        return self.cipher.encrypt \
            if self.mode == Mode.ENCRYPT \
            else self.cipher.decrypt

    @property
    def encrypter(self):
        return SequentialBlockProcessor(Actions([self.crypt]))

    @property
    def writer(self) -> Writer:
        # When we don't know the size we have to stream
        if isinstance(self.origin.storage, StreamStorage):
            if isinstance(self.target.storage, FileStorage):
                return self._writer_file()
            elif isinstance(self.target.storage, StreamStorage):
                return self._writer_streamed()

        # When we do know the size of the stream
        elif isinstance(self.origin.storage, FileStorage):
            if isinstance(self.target.storage, FileStorage):
                return self._writer_mapped()
            elif isinstance(self.target.storage, StreamStorage):
                return self._writer_streamed()

        raise NotImplementedError()

    def _writer_file(self):
        def _writer(blocks: Iterator[Block], target: Source):
            yield from FileWriter(target.storage.path).map(blocks)

        return _writer

    def _writer_streamed(self):
        def _writer(blocks: Iterator[Block], target: Source):
            yield from StreamWriter(target.storage.stream()).map(blocks)

        return _writer

    def _writer_mapped(self):
        def _writer(blocks: Iterator[Block], target: Source):
            with self.target.stream('wb+') as target_stream:
                writer = MappedWriter(target_stream, self.target.size)
                yield from map(writer, blocks)

        return _writer

    def execute(self):
        logging.info(
            '%s %s to %s using %s',
            self.mode, self.origin_storage,
            self.target_storage, self.cipher.cipher
        )
        blocks = self.reader.iter_storage(self.origin.storage)
        blocks = self.encrypter(blocks)
        blocks = self.writer(blocks, self.target)
        consume(blocks)


def error(msg, is_exit=True):
    logging.error(msg)
    if is_exit:
        sys.exit()


def open_storage(handle: Any) -> Storage:
    """Create a Storage object from low level data resource"""
    if isinstance(handle, io.IOBase):
        return StreamStorage(handle)
    elif isinstance(handle, Path):
        return FileStorage(handle)
    else:
        raise NotImplementedError()


def open_origin(name: str) -> Storage:
    """Open a data resource from a string identifier to read from"""
    if name is None or name == '-':
        handle = sys.stdin.buffer
    else:
        handle = Path(name)
    return open_storage(handle)


def open_target(name: Optional[str]) -> Storage:
    """Open a data resource from a string identifier to write to"""
    if name is None or name == '-':
        handle = sys.stdout.buffer
    else:
        handle = Path(name)
    return open_storage(handle)


def parse_args():
    """Parses the command line and checks some values.
    Returns parsed options and positional arguments: (opts, args)"
    """
    parser = ArgumentParser(usage="%(prog)s [options] ARG ARG")

    parser.add_argument(
        "--encrypt", action="store_true", default=False,
        help="Convert a plain data version into an encrypted one"
    )
    parser.add_argument(
        "--decrypt", action="store_true", default=False,
        help="Take back an encrypted version into a plain one"
    )
    parser.add_argument(
        "-v", "--verbose", dest="verbose", action="count", default=0,
        help="Use repeated times to increase the verbosity"
    )
    parser.add_argument(
        "--key", required=True,
        help="Arbitrary string used as cipher key for encryption/decryption"
    )
    parser.add_argument(
        '-o', "--origin", default=None,
        help='Source of the encrypted/decripted data'
    )
    parser.add_argument(
        '-t', "--target", default=None,
        help='Destination of the encrypted/decrypted data')

    args = parser.parse_args()

    # Configure logging
    logging_levels = {0: logging.WARNING, 1: logging.INFO, 2: logging.DEBUG}
    level = logging_levels[args.verbose if args.verbose < 3 else 2]
    logging.basicConfig(level=level, format=_LOGGING_FMT_)

    if not (args.encrypt or args.decrypt):
        error('Either --encrypt or --decrypt options are mandatory')
    elif args.encrypt and args.decrypt:
        error('Options --encrypt or --decrypt are mutually exclusive')

    args.mode = Mode.ENCRYPT if args.encrypt else Mode.DECRYPT
    args.origin = open_origin(args.origin)
    args.target = open_target(args.target)

    return args


def main():
    args = parse_args()

    key = hashlib.sha256(args.key.encode('utf8')).digest()  # 32 bytes
    cipher = BlockCipher(Cipher(key), Nonce())

    context = Context(args.mode, cipher, args.origin, args.target)
    context.execute()


if __name__ == "__main__":
    main()
