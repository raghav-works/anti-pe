# EMBER v2 feature audit

Authoritative specification: Elastic EMBER `ember/features.py`, commit
`d97a0b523de02f3fe5ea6089d080abacab6ee931` (BSD 2-Clause).

| Group | Offset | Dim | Previous implementation | Official implementation | Match before change | Required change |
|---|---:|---:|---|---|---|---|
| ByteHistogram | 0:256 | 256 | Normalized byte counts | Normalized byte counts | Yes | Retain semantics and validate dimension |
| ByteEntropyHistogram | 256:512 | 256 | Full-byte entropy and normalized windows | 16-bin coarse counts; entropy uses fixed 2048 divisor; normalize once | No | Use official block algorithm |
| StringExtractor | 512:616 | 104 | Length histogram, custom scalars, padding | Count, mean, total, normalized 96 printable distribution, entropy, path/URL/registry/MZ counts | No | Replace group |
| GeneralFileInfo | 616:626 | 10 | Section and library counts in different order | Size, virtual size, debug, exports, imports, relocations, resources, signature, TLS, symbols | No | Replace fields and order |
| HeaderFileInfo | 626:688 | 62 | Custom scalar/one-hot values and padding | 1 timestamp, five 10-bin FeatureHasher groups, 11 optional-header scalars | No | Replace group |
| SectionInfo | 688:943 | 255 | Known names, aggregates, SHA-256 hashing | Five counts and five 50-bin FeatureHasher groups | No | Replace group |
| ImportsInfo | 943:2223 | 1280 | SHA-256 modulo hashing and indicators | FeatureHasher 256 libraries + 1024 qualified imports | No | Replace group |
| ExportsInfo | 2223:2351 | 128 | SHA-256 modulo hashing and counters | FeatureHasher 128 over clipped names | No | Replace group |
| DataDirectories | 2351:2381 | 30 | Size plus presence | Size and RVA for first 15 directories | No | Replace group |

The previous concatenation padded or truncated to 2,381, hiding group errors.
The corrected implementation rejects any group or whole-vector dimension
mismatch and rejects non-finite or non-float32 output.

## Compatibility status

The development runtime currently uses LIEF 0.17.6. Elastic states that feature
version 2 was generated with LIEF 0.9.0 and warns that parser versions may
produce different metadata. Official transformation semantics are implemented,
but full golden-vector parity has not been established. Metadata therefore sets
`feature_parity_verified` to `false`; production readiness is conditional.

