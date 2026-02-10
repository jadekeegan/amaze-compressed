# Amaze Compressed

This repository is a fork off of the `amaze` Rust implementation of AMF used to create benchmarks that are more comparable to other implementation. It makes the following modifications to the original repository:

- Compress all `RistrettoPoint`s to their 32-byte `CompressedRistretto` representation
- Generate a random string for messages based on an input message length.

The first modification is critical to ensuring that communication costs are in line with the original AMF paper. Because the `RistrettoPoint` is represented as a 160-byte struct for faster computation, the current `amaze` implementation (which does not compress) is quite a bit more bloated than the original. Further, compression and decompression incurs additional overhead that will increase the computation time. Since most implementations use `CompressedRistretto`s, fair comparison necessitates compression!

The second modification makes benchmarking with a specific message byte size simpler. The original implementation simply uses a "Hello, world!" string for benchmarking, but research typically prefers more specific byte sizes for analysis. Those who would like to run these benchmarks with other message sizes will still need to modify the file, but this hopefully makes the process a little more convenient.

Note that the original implementation does contain a `codec` file for serialized versions of the signature. However, the serialization is a bit convoluted as it assumes Scalars/Ristrettos cannot be represented as bytes. This is not case. Scalars have a built in `as_bytes` method, and Ristrettos can be converted to `CompressedRistretto`s, which in turn has a built in `as_bytes` method.

See the original repository for more information about their implementation: https://github.com/initsecret/amaze.
