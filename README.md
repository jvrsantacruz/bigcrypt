bigcrypt
========

Encrypt large files efficiently using libsodium

The goal of _bigcrypt_ is to be able to encrypt really big files that would
exceed the maximum length of the encrypted message that is safe to use.
It does so by encrypting it separatedly by [splitting](#encryption) the file
in blocks and encrypting them separatedly using each the same key but a
different nonce.
This also allows for [parallel processing](#engines) by having a pool of
processes workon on different blocks, allowing for a better use of CPU.
It always tries to perform the [io](#io) in the most efficient way by allowing
to read stream of piped data or trying to use [mmap][] when possible.

    ./crypted --encrypt --origin ./plain.txt --target crypt.data
    ./crypted --decrypt --origin ./crypt.data --target plain.txt

    cat plain.txt | ./crypted --encrypt | ./crypted --decrypt > same.txt

## Encryption

The file is splitted in blocks all of the same size, except the last one.
Every block will be read, processed and written, independently in an arbitrary
order (except when using the _sequential_ [engine](#engines) or [streamed
io](#io)).

The default _block size_ is _64MiB_ but this can be adjusted to match specific
needs by using the _--block-size_ option.

This _block size_ refers to the plain data, the block size of the encrypted
file might be bigger when they include validation info or the nonce depending
on the encryption [scheme](#schemes) used.

## Schemes

_bigcrypt_ is prepared to be extended by using different algorithms and modes
for encrypting the data. Every strategy is named an encryption _scheme_ and
implements different algorithms or combines them to encrypt the data.

Currently only the [sodium scheme](#sodium-scheme) is implemented.

### Sodium scheme

It uses libsodium default secret key cryptography.

The algorithm used to encrypt the data used by libsodium is
_xchacha20poly1035_ and uses 32 bit keys and 24 bit nonces.
Nonces are chosen randomly and then incremented for every block, so every
block uses a different nonce, taking care of not repeating them.

The block size limit of this scheme of encryption is set the
[message limit][] for the algorithm of a bit less of 256 GiB.

The max total size of the data to be encrypted is then determined
by this combination of how many blocks limited
by the number of 2^24 nonces and max block size which is 256 GiB,
making it 2^56 bits or around 9 Petabytes of max theorical file size.

The max theorical size using the default block size of 64 MiB is of 1
Petabyte.

## Engines

_bigcrypt_ has different "_engines_"  that allow for different ways of
processing the blocks during the encryption and decryption.
The list of available engines is:

- _process_ (default)
- _threads_
- _sequential_

_process_ is the default _engine_, and uses a set of child processes to
encrypt every block independently. As the encryption/decryption operation
tends to be a CPU bound task, this is the most effective way of processing a
big file, not suffering from the [GIL][]. Depending on the [io](#io) used,
every process might also write the results in the child process or pass it
back to the main thread.

_threads_ is similar to _process_ but uses a pool of threads instead
of subprocesses.

_sequential_ makes blocks to be processed in order, one after another. It only
uses the main thread for reading, encrypting and writing the data.

The same engine can although be using different strategy on how to combine
different algorithms or changes related to how [io](#io) is performed.

## IO

The data to be encrypted or decrypted can be passed to the program in various
ways to be read, passed to the cipher and written back. _bigcrypt_ tries to
use the most effective strategy for every situation, although some of them
might present limitations depending on whether the total size of the file is
known beforehand.

When the source target is a file from an existing path in the filesystem, it's
total size is known and it allows us to use [mmap][] for reading it.  When
writing the result into to a file, [mmap][] is also used and expanded to the
expected size using [fallocate][]. These are shared among threads and child
processes both for reading and writing concurrently.

    bigcrypt --encrypt --origin ./plain.txt --target ./crypt.data

In the case of piping plain data as a stream into the process, the total size
is unknown, an so is read sequentially in chunks of _block size_ from the main
process and then processed.

Not knowing the total amount of data disables us from using a mapping in case
that it were to a file in the disk, and so the target file is truncated and
written using regular write calls. This file descriptor for writing is shared
with threads and child processes and written concurrently.

    cat ./plain.txt | bigcrypt --encrypt --target ./crypt.data

This does not always happen when decrypting, as the encrypted file might
include a [header](#headers) stating the total size of the file, and so the
target can be mapped.

    cat ./crypt.data | bigcrypt --decrypt --target ./plain.txt

When the output goes to stdout, blocks are written to the stream by the main
process _in order_. This means that some buffering might take place when the
blocks are not tackled in order, a thing that might happen when using the
_process_ or _threads_ [engines](#engines).

    cat ./crypt.data | bigcrypt --decrypt > ./plain.txt

Both reading from stdin and writing to stdout makes the total size to be
unknown and not placed in the encrypted [header](#headers):

    cat ./plain.txt | bigcrypt --encrypt | bigcrypt --decrypt > ./plain.txt

## Headers

Encrypted files include a small header that determines which kind of
encryption was used to generate it, the block size and the total length of the
file including the header, when available.

## Usage

    usage: crypted.py [options] ARG ARG

    optional arguments:
    -h, --help            show this help message and exit
    --encrypt             Convert a plain data version into an encrypted one
    --decrypt             Take back an encrypted version into a plain one
    --scheme {sodium}     Encryption scheme version to be used
    --key KEY             Arbitrary string used as cipher key for
                            encryption/decryption
    --engine {sequential,process,threads}
                            Parallelization method
    --block-size BLOCK_SIZE
                            Block size bytes for the encrypted data: 67108864
    --total-size TOTAL_SIZE
                            Total size of the origin data source in bytes
    --pool-size POOL_SIZE
                            Number of threads/processes when using parallel
                            processing: 5
    -o ORIGIN, --origin ORIGIN
                            Source of the encrypted/decripted data
    -t TARGET, --target TARGET
                            Destination of the encrypted/decrypted data
    -v, --verbose         Use repeated times to increase the verbosity

## Development

This project uses [pyproject.toml][] and [poetry][] to manage its
dependencies. Install [poetry][] in your system in order to setup a
development environment for this project.

Run the tests with:

    poetry run tox

For development, you can try just using more basic operations:

    poetry install
    poetry run ./test.sh

Use other interpreters by selecting which poetry environment to use:

    poetry env use python3.8

[GIL]: http://man7.org/linux/man-pages/man2/mmap.2.html
[fallocate]: http://man7.org/linux/man-pages/man2/mmap.2.html
[mmap]: http://man7.org/linux/man-pages/man2/mmap.2.html
[message limit]: https://github.com/jedisct1/libsodium/blob/master/src/libsodium/include/sodium/crypto_secretstream_xchacha20poly1305.h#L32
[poetry]: https://python-poetry.org
[pyproject.toml]: https://www.python.org/dev/peps/pep-0518/
