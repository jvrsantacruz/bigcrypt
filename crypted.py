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
import struct
from enum import Enum
from argparse import ArgumentParser
from pathlib import Path
from multiprocessing import Pool
from multiprocessing.pool import ThreadPool
import fallocate
import collections
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import (Iterator, IO, List, Tuple, Callable, Optional, Any, Dict,
                    Union, ClassVar)

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


@dataclass()
class Block:
    """Basic encryption unit"""
    n: int = field()
    size: int = field(compare=False)
    block_size: int = field(compare=False, repr=False)
    data: bytes = field(compare=False, repr=False)


@dataclass()
class MemoryBlock(Block):
    """Block that keeps the data in memory"""


@dataclass(init=False)
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
        offset: int,
        mem = mmap.mmap,
        data: bytes=b'',
    ):
        self.n = n
        self.size = size
        self.block_size = block_size
        self.offset = offset + n * block_size
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
        return self._mem[self.offset:self.offset + self.size]

    @data.setter
    def data(self, data: bytes) -> bytes:
        self._mem[self.offset:self.offset + self.size] = data


class Version(Enum):
    sodium = 0


class Header:
    format = None
    fields = None
    size = None

    @classmethod
    def from_stream(cls, stream: IO[bytes]):
        buffer = stream.read(cls.size)
        values = struct.unpack(cls.format, buffer)
        return cls(**dict(zip(cls.fields, values)))

    def to_stream(self, stream: IO[bytes]):
        values = tuple(getattr(self, field) for field in self.fields)
        values = [(0 if v is None else v) for v in values]
        buffer = struct.pack(self.format, *values)
        stream.write(buffer)


class VersionHeader(Header):
    format = '<I'
    fields = ('version',)
    size = struct.calcsize(format)

    def __init__(self, version: int):
        self.version = version


class Payload(Header):
    version = None

    @classmethod
    def cls_from_version(cls, version: int):
        for header_cls in cls.__subclasses__():
            if header_cls.version == version:
                return header_cls
        raise ValueError(
            f'Unknown header version {version} it should be one '
            f'of: {" ".join(v.name for v in Version)}'
        )


class SodiumPayload(Payload):
    version = Version.sodium.value
    format = '<IQ'
    size = struct.calcsize(format)
    fields = ('block_size', 'total_size')

    def __init__(self, block_size: int, total_size: Optional[int]=None):
        super().__init__()
        self.block_size = block_size
        # 0 size is the same as not known
        self.total_size = None if total_size is 0 else total_size


@dataclass
class ComposedHeader:
    header: VersionHeader = field()
    payload: Payload = field()

    @classmethod
    def from_stream(cls, stream: IO[bytes]):
        header = VersionHeader.from_stream(stream)
        payload_cls = Payload.cls_from_version(header.version)
        payload = payload_cls.from_stream(stream)
        return cls(header, payload)

    def to_stream(self, stream: IO[bytes]):
        self.header.to_stream(stream)
        self.payload.to_stream(stream)

    @cached_property
    def version(self) -> Version:
        return Version(self.header.version)

    @cached_property
    def size(self) -> int:
        return self.header.size + self.payload.size


@dataclass
class Meta:
    header_size: int = field()
    block_size: int = field()
    block_overhead: int = field()
    total_size: Optional[int] = field(default=None)
    total_blocks: Optional[int] = field(default=None)

    def __post_init__(self):
        if self.total_blocks is None:
            self.total_blocks = self.get_total_blocks()

    @cached_property
    def total_overhead(self) -> Optional[int]:
        if self.total_blocks is not None:
            return self.total_blocks * self.block_overhead

    @cached_property
    def data_size(self) -> Optional[int]:
        return self.total_blocks * self.block_overhead

    def get_total_blocks(self) -> Optional[int]:
        if self.total_size is not None:
            return self.total_size // self.block_size + \
                (0 if self.total_size % self.block_size == 0 else 1)


@dataclass
class Reader:
    """Create blocks from a given stream"""
    stream: IO[bytes] = field()
    block_size: int = field()
    offset: int = field(default=0)
    total_size: Optional[int] = field(default=None)

    def __call__(self) -> Iterator[Block]:
        raise NotImplementedError()


@dataclass
class StreamReader(Reader):
    """Create blocks from a file handler"""

    def __call__(self) -> Iterator[MemoryBlock]:
        n = 0
        data = self.stream.read(self.block_size)
        while data:
            yield MemoryBlock(
                n=n,
                size=len(data),
                block_size=self.block_size,
                data=data
            )
            data = self.stream.read(self.block_size)
            n += 1


@dataclass
class MappedReader(Reader):
    """Create memory mapped blocks from a file handler

This requires the file to exist in the filesystem and to know it's full size.
A mmap is created for the file and registered at the MemoryRegistry.
    """
    def __post_init__(self):
        if self.total_size is None:
            raise ValueError('MappedReader needs total_size to be known')

        fileno = self.stream.fileno()  # FIXME
        self.stream = fileno
        self.mem_id = memory_registry.add(
            mmap.mmap(
                fileno=fileno,
                length=0,  # same size as the file
                flags=mmap.MAP_SHARED,
                prot=mmap.PROT_READ,
            )
        )

    def __call__(self) -> Iterator[MappedBlock]:
        mem = memory_registry[self.mem_id]
        for n, size in self.calculate_blocks(self.total_size):
            yield MappedBlock(
                n=n,
                size=size,
                block_size=self.block_size,
                offset=self.offset,
                mem=mem,
            )

    def calculate_blocks(self, total_size: int) -> Iterator[Tuple[int, int]]:
        last_block = 0
        whole_blocks = total_size // self.block_size
        for n in range(whole_blocks):
            last_block = n
            yield n, self.block_size

        last_block_size = total_size % self.block_size
        if last_block_size:
            last_block = 0 if not whole_blocks else last_block + 1
            yield last_block, last_block_size


@dataclass
class Writer:
    """Write a single block into an storage"""
    concurrent: ClassVar[bool] = False

    stream: IO[bytes] = field()
    offset: int = field(default=0)
    total_size: Optional[int] = field(default=None)

    def __call__(self, block: Block) -> Iterator[Block]:
        raise NotImplementedError()


@dataclass
class FileWriter(Writer):
    """Write a single block into a given file

It stores the path instead of the file handler to avoid problems while
writing in child processes.
    """
    concurrent: ClassVar[bool] = True

    def __post_init__(self):
        self.stream = self.stream.name # FIXME

    def __call__(self, block: Block) -> List[Block]:
        with open(self.stream, 'wb+') as stream:
            stream.seek(self.offset + block.n * block.block_size)
            stream.write(block.data)
        return [block]


@dataclass
class StreamWriter(Writer):
    """Write blocks into a stream, in order

This class is not safe in concurrency mode.
    """
    concurrent: ClassVar[bool] = False

    def __post_init__(self):
        self._n = 0
        self._cache = {}

    def __call__(self, block: Block) -> List[Block]:
        written_blocks = []
        self._cache[block.n] = block
        block = self._cache.get(self._n)
        while block is not None:
            self.stream.write(block.data)
            self._n += 1
            written_blocks.append(block)
            block = self._cache.get(self._n)
        return written_blocks


@dataclass
class MappedWriter(Writer):
    """Memory mapped writer

It writes the block into an existing file via memory map.
The total size must be known and the file should be already of the target size.
    """
    concurrent: ClassVar[bool] = True

    def __post_init__(self):
        if self.total_size is None:
            raise ValueError('MappedWriter needs total_size')

        fileno = self.stream.fileno()
        self.stream = fileno  # FIXME
        # Make sure the target file is of the right size without
        # taking up the space, the file it's just a big "hole"
        fallocate.fallocate(fileno, 0, self.total_size)
        self.mem_id = memory_registry.add(
            mmap.mmap(
                fileno=fileno,
                length=self.total_size,
                flags=mmap.MAP_SHARED,
                prot=mmap.PROT_WRITE,
            )
        )

    def __call__(self, block: Block) -> List[MappedBlock]:
        return [MappedBlock(
            n=block.n,
            size=block.size,
            block_size=block.block_size,
            data=block.data,
            offset=self.offset,
            mem=memory_registry[self.mem_id],
        )]


class MappedAnonWriter(MappedWriter):
    """Memory mapped writer into memory

It saves the block into an anonymous memory region.
Total size must be known, but the file is not persisted.
This is useful to pass the memory among processes.
    """
    def __post_init__(self):
        self.mem_id = memory_registry.add(
            mmap.mmap(
                fileno=-1,
                length=total_size - self.offset,
                flags=mmap.SHARED,
                prot=mmap.PROT_READ | mmap.PROT_WRITE,
            )
        )


@dataclass
class OpenStorage:
    header: Header = field()
    reader: Optional[Reader] = field(default=None)
    writer: Optional[Writer] = field(default=None)


@dataclass
class Storage:
    """Data storage representation

It abstracts the different possible data devices.

This should always be able to open a byte stream from the underlaying resource.
Total size might not be available for pipes and streams.
The max_blocks represents possible limitations in the amount of blocks that can
be processed.
    """
    @property
    def size(self) -> Optional[int]:
        return None

    @contextmanager
    def reader(
        self,
        has_header: bool=False,
        block_size: Optional[int]=None,
        total_size: Optional[int]=None
    ):
        raise NotImplementedError()

    @contextmanager
    def writer(
        self,
        header: Optional[Header]=None,
        total_size: Optional[int]=None,
    ):
        raise NotImplementedError()


class S3Storage(Storage):
    """Represents an existing S3 file"""
    max_blocks = 10000


@dataclass
class FileStorage(Storage):
    """Represents a file in the filesystem"""
    path: Path = field()

    @property
    def size(self) -> int:
        return self.path.stat().st_size

    @contextmanager
    def reader(
        self,
        has_header: bool=False,
        block_size: Optional[int]=None,
        total_size: Optional[int]=None
    ):
        with self.path.open('rb+') as stream:
            header = None
            if has_header:
                header = ComposedHeader.from_stream(stream)

            yield OpenStorage(
                header=header,
                reader=MappedReader(
                    stream=stream,
                    block_size=header.payload.block_size if header else block_size,
                    offset=header.size if header else 0,
                    total_size=self.size - header.size if header else self.size ,
                ))

    @contextmanager
    def writer(
        self,
        header: Optional[Header]=None,
        total_size: Optional[int]=None,
    ):
        with self.path.open('wb+') as stream:
            if header is not None:
                header.to_stream(stream)
                total_size = header.payload.total_size

            writer_cls = FileWriter if total_size is None else MappedWriter
            yield OpenStorage(
                header=header,
                writer=writer_cls(
                    stream=stream,
                    offset=header.size if header else 0,
                    total_size=total_size,
                )
            )


@dataclass
class StreamStorage(Storage):
    """Represents an existing open file"""
    stream: IO[bytes] = field()

    @contextmanager
    def reader(
        self,
        has_header: bool=False,
        block_size: Optional[int]=None,
        total_size: Optional[int]=None,
    ):
        header = None
        if has_header:
            header = ComposedHeader.from_stream(self.stream)

        yield OpenStorage(
            header=header,
            reader=StreamReader(
                stream=self.stream,
                block_size=header.payload.block_size if header else block_size,
                offset=header.size if header else 0,
            ),
        )

    @contextmanager
    def writer(
        self,
        header: Optional[Header]=None,
        total_size: Optional[int]=None,
    ):
        if header is not None:
            header.to_stream(self.stream)

        yield OpenStorage(
            header=header,
            writer=StreamWriter(stream=self.stream)
        )


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


class Engine(Enum):
    SEQUENTIAL = 1
    PROCESS = 2
    THREADS = 3


@dataclass
class BlockProcessor:
    """Process blocks by applying a set of actions"""
    engine: Engine = field()
    callback: Callable[[Block], Block] = field()
    reader: Reader = field()
    writer: Writer = field()

    def __call__(self) -> Iterator[Optional[Block]]:
        if self.engine == Engine.SEQUENTIAL:
            return self.sequential()
        elif self.engine == Engine.PROCESS:
            return self.multiprocess()
        elif self.engine == Engine.THREADS:
            return self.multithread()
        else:
            raise ValueError(f'Engine {self.engine} is not implemented')

    def sequential(self) -> Iterator[Optional[Block]]:
        """Process blocks one after another"""
        return (self.writer(self.callback(block)) for block in self.reader())

    def multiprocess(self) -> Iterator[Optional[Block]]:
        """Process blocks using a pool of processes"""
        yield from self._pooled_process(Pool)

    def multithread(self) -> Iterator[Optional[Block]]:
        """Process blocks using a pool of threads"""
        yield from self._pooled_process(ThreadPool)

    def _pooled_process(self, pool_cls) -> Iterator[Optional[Block]]:
        with pool_cls(10) as pool:
            if self.writer.concurrent:
                callback = Callback(self.writer, self.callback)
                yield from pool.imap_unordered(callback, self.reader())
            else:
                blocks = pool.imap_unordered(self.callback, self.reader())
                yield from (self.writer(block) for block in blocks)


@dataclass
class Callback:
    """Compose writer and callback in a picklable way"""
    writer: Writer
    callback: Writer

    def __call__(self, block: Block) -> Block:
        return self.writer(self.callback(block))


class Scheme:
    version: Version = None
    cipher_cls = None
    nonce_cls = None
    header_cls = None
    payload_cls = None
    header_size = None

    @classmethod
    def from_version(cls, version: Union[Version, int, str]) -> 'Scheme':
        if isinstance(version, int):
            version = Version(version)
        elif isinstance(version, str):
            version = Version[version]

        for scheme_cls in cls.__subclasses__():
            if scheme_cls.version == version:
                return scheme_cls()

        raise ValueError(f'Scheme {version} is not implemented')

    @cached_property
    def header_size(self) -> int:
        return self.header_cls.size + self.payload_cls.size

    def cipher(self, key: bytes) -> BlockCipher:
        return BlockCipher(self.cipher_cls(key=key), self.nonce_cls())

    def header(self, *args, **kwargs) -> Header:
        return ComposedHeader(
            self.header_cls(self.version.value),
            self.payload_cls(*args, **kwargs),
        )


class SodiumScheme(Scheme):
    version: Version = Version.sodium
    cipher_cls = Cipher
    nonce_cls = Nonce
    header_cls = VersionHeader
    payload_cls = SodiumPayload
    header_size = VersionHeader.size + SodiumPayload.size


class Mode(Enum):
    ENCRYPT = 1
    DECRYPT = 2

    def __str__(self):
        return 'Encrypt' if self == Mode.ENCRYPT else 'Decrypt'


@dataclass
class Context:
    mode: Mode = field()
    engine: Engine = field()
    scheme: Version = field()
    key: bytes = field()
    block_size: Optional[int] = field(default=None)
    total_size: Optional[int] = field(default=None)


def encrypt(context: Context, origin: Storage, target: Storage):
    with origin.reader(
        block_size=context.block_size,
        has_header=context.mode == Mode.DECRYPT,
        total_size=context.total_size,
    ) as source:
        scheme = Scheme.from_version(context.scheme)
        cipher = scheme.cipher(context.key)

        source_block_size = context.block_size
        source_total_size = origin.size or context.total_size

        total_blocks = None
        if source_total_size:
            total_blocks = calculate_total_blocks(
                source_block_size, source_total_size
            )

        dest_block_size = source_block_size + cipher.block_overhead
        dest_total_size = None
        if source_total_size:
            dest_total_size = (
                scheme.header_size +
                source_total_size +
                total_blocks * cipher.block_overhead
            )

        header = scheme.header(
            block_size=dest_block_size,
            total_size=dest_total_size,
        )
        with target.writer(header=header) as dest:
            processor = BlockProcessor(
                context.engine, cipher.encrypt, source.reader, dest.writer
            )
            consume(processor())


def decrypt(context: Context, origin: Storage, target: Storage):
    with origin.reader(has_header=True) as source:
        scheme = Scheme.from_version(source.header.version)
        cipher = scheme.cipher(context.key)

        block_size = source.header.payload.block_size
        source_total_size = (
            source.header.payload.total_size or
            origin.size or
            context.total_size
        )

        total_blocks = 0
        if source_total_size:
            data_size = source_total_size - scheme.header_size
            total_blocks = calculate_total_blocks(block_size, data_size)

        dest_total_size = None
        if source_total_size:
            dest_total_size = (
                source_total_size -
                scheme.header_size -
                total_blocks * cipher.block_overhead
            )

        with target.writer(total_size=dest_total_size) as dest:
            processor = BlockProcessor(
                context.engine, cipher.decrypt, source.reader, dest.writer
            )
            consume(processor())


def calculate_total_blocks(block_size: int, total_size: int) -> int:
    return total_size // block_size +\
        (0 if total_size % block_size == 0 else 1)


def error(msg, is_exit=True):
    logging.error(msg)
    if is_exit:
        sys.exit()


def consume(iterable):
    """Efficiently iterate over a sequence discarding the results"""
    collections.deque(iterable, maxlen=0)


def printer(block: Block) -> Block:
    """Action of printing a single block for debug"""
    print(block, file=sys.stderr)
    return block


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


def open_storage(handle: Any, **kwargs) -> Storage:
    """Create a Storage object from low level data resource"""
    if isinstance(handle, io.IOBase):
        return StreamStorage(handle, **kwargs)
    elif isinstance(handle, Path):
        return FileStorage(handle, **kwargs)
    else:
        raise NotImplementedError()


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
        "--scheme",
        default=Version.sodium.name,
        choices=[v.name.lower() for v in Version],
        help="Encryption scheme version to be used"
    )
    parser.add_argument(
        "--key", required=True,
        help="Arbitrary string used as cipher key for encryption/decryption"
    )
    parser.add_argument(
        "--engine", default=Engine.PROCESS.name.lower(),
        choices=[e.name.lower() for e in Engine],
        help="Parallelization method"
    )
    parser.add_argument(
        "--block-size", default=DEFAULT_BLOCK_SIZE, type=int,
        help=f"Block size bytes for the encrypted data: {DEFAULT_BLOCK_SIZE}"
    )
    parser.add_argument(
        "--total-size", default=None,
        help="Total size of the origin data source in bytes",
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
        help='Destination of the encrypted/decrypted data'
    )
    parser.add_argument(
        "-v", "--verbose", dest="verbose", action="count", default=0,
        help="Use repeated times to increase the verbosity"
    )

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
    args.scheme = Version[args.scheme]
    args.engine = Engine[args.engine.upper()]
    args.origin = open_origin(args.origin)
    args.target = open_target(args.target)
    if args.total_size:
        args.total_size = int(args.total_size)

    return args


def main():
    args = parse_args()

    key = hashlib.sha256(args.key.encode('utf8')).digest()  # 32 bytes
    context = Context(
        mode=args.mode,
        engine=args.engine,
        scheme=args.scheme,
        key=key,
        block_size=args.block_size,
        total_size=args.total_size,
    )
    logging.info('%s from %s to %s', context, args.origin, args.target)
    if context.mode == Mode.ENCRYPT:
        encrypt(context, args.origin, args.target)
    else:
        decrypt(context, args.origin, args.target)


if __name__ == "__main__":
    main()
