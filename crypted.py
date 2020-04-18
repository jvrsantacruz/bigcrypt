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
from dataclasses import dataclass, field
from typing import Iterator, IO, List, Tuple, Callable, Optional, Any, Dict

DEFAULT_POOL_SIZE = 5
DEFAULT_BLOCK_SIZE = 64 * 2**20 # 64 MiB
_LOGGING_FMT_ = '%(asctime)s %(levelname)-8s %(message)s'


@dataclass
class MemoryRegistry:
    """Global registry of maps to avoid pickling objects

The mmap objects are not pickable and thus usable in queues.
Threads and child processes should have the reference too.
Be sure to register your maps BEFORE starting child processes.
    """
    objs: Dict[int, mmap.mmap] = field(default_factory=dict)

    def __getitem__(self, obj_id: int) -> mmap.mmap:
        return self.objs[obj_id]

    def add(self, mem: mmap.mmap) -> int:
        obj_id = id(mem)
        self.objs.setdefault(obj_id, mem)
        return obj_id


memory_registry = MemoryRegistry()


@dataclass(eq=True, order=True)
class Block:
    """Basic encryption unit"""
    n: int = field()
    size: int = field(compare=False)
    block_size: int = field(compare=False, repr=False)
    data: bytes = field(compare=False, repr=False)


@dataclass(eq=True, order=True)
class MemoryBlock(Block):
    """Block that keeps the data in memory"""


@dataclass(eq=True, order=True, init=False)
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


class S3Storage(Storage):
    """Represents an existing S3 file"""
    max_blocks = 10000


@dataclass
class FileStorage(Storage):
    """Represents a file in the filesystem"""
    path: Path = field()

    def stream(self, *args, **kwargs) -> IO[bytes]:
        return self.path.open(*args, **kwargs)

    @property
    def size(self) -> int:
        return self.path.stat().st_size


@dataclass(init=False)
class StreamStorage(Storage):
    """Represents an existing open file"""

    def __init__(self, stream: IO[bytes]):
        self._stream = stream

    def stream(self) -> IO[bytes]:
        return self._stream


@dataclass()
class Reader:
    """Create blocks from a given stream"""
    block_size: int = field()

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
        return self(storage.stream('rb+'))

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

    def __init__(self, actions: Actions, pool: Pool):
        super().__init__(actions)
        self.pool = pool

    def __call__(self, blocks: Iterator[Block]) -> Iterator[Optional[Block]]:
        return self.pool.imap_unordered(self.actions, blocks)


class ThreadBlockProcessor(BlockProcessor):
    """Process blocks using a pool of threads"""

    def __init__(self, actions: Actions, pool: ThreadPool):
        super().__init__(actions)
        self.pool = pool

    def __call__(self, blocks: Iterator[Block]) -> Iterator[Optional[Block]]:
        return self.pool.imap_unordered(self.actions, blocks)


class Writer:
    """Write a single block into an storage"""

    def __call__(self, block: Block) -> Block:
        raise NotImplementedError()

    def map(self, blocks: Iterator[Block]) -> Iterator[Block]:
        return map(self, blocks)

    def __repr__(self):
        return f'{type(self).__name__}()'


class FileWriter(Writer):
    """Write a single block into a given file

It stores the path instead of the file handler to avoid problems while
writing in child processes.
    """
    @classmethod
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

    def __repr__(self):
        return f'{type(self).__name__}({self.path})'


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

    def __repr__(self):
        return f'{type(self).__name__}({self._stream})'


class MappedWriter(Writer):
    """Memory mapped writer

It writes the block into an existing file via memory map.
The total size must be known and the file should be already of the target size.
    """
    @classmethod
    def from_storage(cls, storage: FileStorage, total_size: int) -> Writer:
        return cls(storage.path.open('wb+'), total_size)

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

    def __repr__(self):
        return f'{type(self).__name__}({self.mem_id})'


class MappedAnonWriter(MappedWriter):
    """Memory mapped writer into memory

It saves the block into an anonymous memory region.
Total size must be known, but the file is not persisted.
This is useful to pass the memory among processes.
    """
    @classmethod
    def from_storage(cls, storage: FileStorage, total_size: int) -> Writer:
        return cls(total_size)

    def __init__(self, total_size: int):
        mem = mmap.mmap(
            -1, total_size, mmap.SHARED, mmap.PROT_READ | mmap.PROT_WRITE
        )
        self.mem_id = memory_registry.add(mem)

    def __repr__(self):
        return f'{type(self).__name__}({self.mem_id})'


@dataclass
class Sizes:
    block_overhead: int
    pool_size: int
    block_size: int

    def validate(self):
        if self.block_size <= self.block_overhead:
            raise ValueError(
                'Bad block_size: encrypted block size cannot be smaller than'
                f' {self.block_overhead + 1}'
            )


class Source:
    """Represents an encrypted data source or destination

It's a wrapper over Storage objects that own the data
but adding the needed features for encryption and decryption.

As with the Storage, the size might not be available.
    """
    def __init__(self, storage: Storage, sizes: Sizes):
        self.storage = storage
        self.sizes = sizes

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
            return (
                self.size // self.block_size +
                (0 if self.size % self.block_size == 0 else 1)
            )

    @cached_property
    def total_overhead(self) -> Optional[int]:
        if self.total_blocks is not None:
            return self.total_blocks * self.sizes.block_overhead

    def __repr__(self):
        return f'{type(self).__name__}({self.storage},{self.sizes})'


class EncryptedSource(Source):
    """Represents an encrypted data source

It is assumed that the contents of the storage are encrypted
    """
    def __init__(
        self,
        storage: Storage,
        sizes: Sizes,
        origin: 'DecryptedSource'=None
    ):
        super().__init__(storage, sizes)
        self.origin = origin

    @cached_property
    def block_size(self) -> int:
        # Use the "round" default block size for the encrypted file
        # Optimize io block size for the encrypted version
        if not self.origin:
            return self.sizes.block_size

        # Take the plain block size and add the encrypting overhead
        # This overhead is due to the validation tag and the nonce
        return self.origin.block_size + self.sizes.block_overhead

    @cached_property
    def size(self) -> Optional[int]:
        if not self.origin:
            return self.storage.size

        # Cannot calculate the size from the original version
        if self.origin.size is None:
            return None

        # Calculate the encrypted total size by adding the accumulated overhead
        # to the size of the plain version of the data
        return self.origin.size + self.origin.total_overhead


class DecryptedSource(Source):
    """Represents the plain version of the data source"""
    def __init__(
        self,
        storage: Storage,
        sizes: Sizes,
        origin: EncryptedSource=None
    ):
        super().__init__(storage, sizes)
        self.origin = origin

    @cached_property
    def block_size(self) -> int:
        base_size = self.sizes.block_size
        if self.origin:
            base_size = self.origin.block_size

        # Plain size is "not round" as it expressed as
        # the encrypted block without the cipher overhead.
        return base_size - self.sizes.block_overhead

    @cached_property
    def size(self) -> Optional[int]:
        if not self.origin:
            return self.storage.size

        # The total size of the plain data is the encrypted size
        # without the accumulated cipher block overhead
        if self.origin.size is not None:
            return self.origin.size -\
                self.origin.total_blocks * self.sizes.block_overhead


class Mode(Enum):
    ENCRYPT = 1
    DECRYPT = 2

    def __str__(self):
        return 'Encrypt' if self == Mode.ENCRYPT else 'Decrypt'


class Engine(Enum):
    SEQUENTIAL = 1
    PROCESS = 2
    THREADS = 3


class Context:
    """Encryption context holds together everything needed for the process"""

    def __init__(
        self,
        mode: Mode,
        engine: Engine,
        cipher: Cipher,
        origin: Storage,
        target: Storage,
        sizes: Sizes,
    ):
        self.mode = mode
        self.engine = engine
        self.cipher = cipher
        self.origin_storage = origin
        self.target_storage = target
        self.sizes = sizes

    @cached_property
    def origin(self) -> Source:
        if self.mode == Mode.ENCRYPT:
            return DecryptedSource(self.origin_storage, self.sizes)
        return EncryptedSource(self.origin_storage, self.sizes)

    @cached_property
    def target(self) -> Source:
        if self.mode == Mode.ENCRYPT:
            return EncryptedSource(
                self.target_storage, self.sizes, origin=self.origin
            )
        return DecryptedSource(
            self.target_storage, self.sizes, origin=self.origin
        )

    @cached_property
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

    @cached_property
    def encrypter(self):
        if self.engine == Engine.SEQUENTIAL:
            return SequentialBlockProcessor(Actions([self.crypt]))
        elif self.engine == Engine.THREADS:
            return ThreadBlockProcessor(
                Actions([self.crypt]), ThreadPool(self.sizes.pool_size)
            )
        elif self.engine == Engine.PROCESS:
            actions = [self.crypt]

            # If we're writing to a file, better to make the
            # same subprocess write to it to avoid passing
            # the data back and forth between parent and children
            if isinstance(self.target.storage, FileStorage):
                if self.origin.size is None:
                    actions.append(
                        FileWriter.from_storage(self.target.storage)
                    )
                else:
                    actions.append(
                        MappedWriter.from_storage(
                            self.target.storage, self.target.size
                        )
                    )

            # Make sure all mmaps are created before starting the pool
            return ProcessBlockProcessor(
                Actions(actions), Pool(self.sizes.pool_size)
            )

        raise NotImplementedError()

    @cached_property
    def writer(self) -> Writer:
        # Use a phony writer when the process already does that
        if self.engine == self.engine.PROCESS and \
                isinstance(self.target.storage, FileStorage):
            return self._writer_dummy()

        # When we don't know the size we have to stream
        if self.origin.size is None:
            if isinstance(self.target.storage, FileStorage):
                return self._writer_file()
            elif isinstance(self.target.storage, StreamStorage):
                return self._writer_streamed()

        # When we know the size, we can use mmap
        else:
            if isinstance(self.target.storage, FileStorage):
                return self._writer_mapped()
            elif isinstance(self.target.storage, StreamStorage):
                return self._writer_streamed()

        raise NotImplementedError()

    def _writer_dummy(self):
        def _writer(blocks: Iterator[Block], target: Source):
            return iter(blocks)

        return _writer

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

def printer(block: Block) -> Block:
    """Action of printing a single block for debug"""
    print(block)
    return block


def consume(iterable):
    """Efficiently iterate over a sequence discarding the results"""
    collections.deque(iterable, maxlen=0)


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
        "--engine", default=Engine.PROCESS,
        choices=[e.name.lower() for e in Engine],
        help="Parallelization method"
    )
    parser.add_argument(
        "--block-size", default=DEFAULT_BLOCK_SIZE, type=int,
        help=f"Block size bytes for the encrypted data: {DEFAULT_BLOCK_SIZE}"
    )
    parser.add_argument(
        "--pool-size", default=DEFAULT_POOL_SIZE, type=int,
        help="Number of threads/processes when using parallel processing:"
        f" {DEFAULT_POOL_SIZE}"
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
    args.engine = Engine[args.engine.upper()]
    args.origin = open_origin(args.origin)
    args.target = open_target(args.target)

    return args


def main():
    args = parse_args()

    key = hashlib.sha256(args.key.encode('utf8')).digest()  # 32 bytes
    cipher = BlockCipher(Cipher(key), Nonce())

    sizes = Sizes(
        pool_size=args.pool_size,
        block_size=args.block_size,
        block_overhead=cipher.block_overhead,
    )
    sizes.validate()
    context = Context(
        mode=args.mode,
        engine=args.engine,
        cipher=cipher,
        origin=args.origin,
        target=args.target,
        sizes=sizes,
    )
    context.execute()


if __name__ == "__main__":
    main()
