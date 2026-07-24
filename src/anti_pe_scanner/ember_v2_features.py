"""Official Elastic EMBER feature-version-2 semantics.

This is an adapted implementation of ``elastic/ember/ember/features.py`` at
commit d97a0b523de02f3fe5ea6089d080abacab6ee931.  The upstream project is
licensed under the BSD 2-Clause License.  The adaptation accepts an already
parsed LIEF binary so endpoint inference does not parse or hash a file twice.
"""

from __future__ import annotations

import re
from time import perf_counter_ns
from typing import Any

import numpy as np
from sklearn.feature_extraction import FeatureHasher

BYTE_HISTOGRAM_DIM = 256
BYTE_ENTROPY_DIM = 256
STRING_DIM = 104
GENERAL_DIM = 10
HEADER_DIM = 62
SECTION_DIM = 255
IMPORTS_DIM = 1280
EXPORTS_DIM = 128
DATA_DIRECTORIES_DIM = 30
EMBER_V2_DIM = 2381

FEATURE_GROUPS = (
    ("histogram", BYTE_HISTOGRAM_DIM),
    ("byteentropy", BYTE_ENTROPY_DIM),
    ("strings", STRING_DIM),
    ("general", GENERAL_DIM),
    ("header", HEADER_DIM),
    ("section", SECTION_DIM),
    ("imports", IMPORTS_DIM),
    ("exports", EXPORTS_DIM),
    ("datadirectories", DATA_DIRECTORIES_DIM),
)
FEATURE_OFFSETS: dict[str, tuple[int, int]] = {}
_offset = 0
for _name, _dim in FEATURE_GROUPS:
    FEATURE_OFFSETS[_name] = (_offset, _offset + _dim)
    _offset += _dim
assert _offset == EMBER_V2_DIM


class FeatureExtractionError(ValueError):
    """Raised when exact model-ready features cannot be produced."""


def _enum_name(value: Any) -> str:
    return str(value).split(".")[-1]


class FeatureType:
    name = ""
    dim = 0

    def raw_features(self, bytez: bytes, lief_binary: Any) -> Any:
        raise NotImplementedError

    def process_raw_features(self, raw_obj: Any) -> np.ndarray:
        raise NotImplementedError

    def feature_vector(self, bytez: bytes, lief_binary: Any) -> np.ndarray:
        return self.process_raw_features(self.raw_features(bytez, lief_binary))


class ByteHistogram(FeatureType):
    name, dim = "histogram", BYTE_HISTOGRAM_DIM

    def raw_features(self, bytez, lief_binary):
        return np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256).tolist()

    def process_raw_features(self, raw_obj):
        counts = np.asarray(raw_obj, dtype=np.float32)
        return counts / counts.sum()


class ByteEntropyHistogram(FeatureType):
    name, dim = "byteentropy", BYTE_ENTROPY_DIM

    def __init__(self, step=1024, window=2048):
        self.step, self.window = step, window

    def _entropy_bin_counts(self, block):
        c = np.bincount(block >> 4, minlength=16)
        p = c.astype(np.float32) / self.window
        wh = np.where(c)[0]
        entropy_bin = int(np.sum(-p[wh] * np.log2(p[wh])) * 4)
        return min(entropy_bin, 15), c

    def raw_features(self, bytez, lief_binary):
        output = np.zeros((16, 16), dtype=np.int64)
        data = np.frombuffer(bytez, dtype=np.uint8)
        if data.shape[0] < self.window:
            entropy_bin, counts = self._entropy_bin_counts(data)
            output[entropy_bin, :] += counts
        else:
            shape = data.shape[:-1] + (data.shape[-1] - self.window + 1, self.window)
            strides = data.strides + (data.strides[-1],)
            blocks = np.lib.stride_tricks.as_strided(data, shape=shape, strides=strides)
            for block in blocks[:: self.step, :]:
                entropy_bin, counts = self._entropy_bin_counts(block)
                output[entropy_bin, :] += counts
        return output.flatten().tolist()

    def process_raw_features(self, raw_obj):
        counts = np.asarray(raw_obj, dtype=np.float32)
        return counts / counts.sum()


class StringExtractor(FeatureType):
    name, dim = "strings", STRING_DIM

    def __init__(self):
        self._allstrings = re.compile(b"[\x20-\x7f]{5,}")
        self._paths = re.compile(b"c:\\\\", re.IGNORECASE)
        self._urls = re.compile(b"https?://", re.IGNORECASE)
        self._registry = re.compile(b"HKEY_")
        self._mz = re.compile(b"MZ")

    def raw_features(self, bytez, lief_binary):
        strings = self._allstrings.findall(bytez)
        if strings:
            lengths = [len(value) for value in strings]
            average = sum(lengths) / len(lengths)
            shifted = [byte - 0x20 for byte in b"".join(strings)]
            counts = np.bincount(shifted, minlength=96)
            total = counts.sum()
            probability = counts.astype(np.float32) / total
            nonzero = np.where(counts)[0]
            entropy = np.sum(-probability[nonzero] * np.log2(probability[nonzero]))
        else:
            average, counts, entropy, total = 0, np.zeros(96), 0, 0
        return {
            "numstrings": len(strings), "avlength": average,
            "printabledist": counts.tolist(), "printables": int(total),
            "entropy": float(entropy), "paths": len(self._paths.findall(bytez)),
            "urls": len(self._urls.findall(bytez)),
            "registry": len(self._registry.findall(bytez)),
            "MZ": len(self._mz.findall(bytez)),
        }

    def process_raw_features(self, raw_obj):
        divisor = float(raw_obj["printables"]) if raw_obj["printables"] > 0 else 1.0
        return np.hstack([
            raw_obj["numstrings"], raw_obj["avlength"], raw_obj["printables"],
            np.asarray(raw_obj["printabledist"]) / divisor, raw_obj["entropy"],
            raw_obj["paths"], raw_obj["urls"], raw_obj["registry"], raw_obj["MZ"],
        ]).astype(np.float32)


class GeneralFileInfo(FeatureType):
    name, dim = "general", GENERAL_DIM

    def raw_features(self, bytez, binary):
        return {
            "size": len(bytez), "vsize": binary.virtual_size,
            "has_debug": int(binary.has_debug),
            "exports": len(binary.exported_functions),
            "imports": len(binary.imported_functions),
            "has_relocations": int(binary.has_relocations),
            "has_resources": int(binary.has_resources),
            "has_signature": int(binary.has_signatures),
            "has_tls": int(binary.has_tls), "symbols": len(binary.symbols),
        }

    def process_raw_features(self, raw):
        return np.asarray([
            raw["size"], raw["vsize"], raw["has_debug"], raw["exports"],
            raw["imports"], raw["has_relocations"], raw["has_resources"],
            raw["has_signature"], raw["has_tls"], raw["symbols"],
        ], dtype=np.float32)


class HeaderFileInfo(FeatureType):
    name, dim = "header", HEADER_DIM

    def raw_features(self, bytez, binary):
        header, optional = binary.header, binary.optional_header
        return {
            "coff": {
                "timestamp": header.time_date_stamps,
                "machine": _enum_name(header.machine),
                "characteristics": [_enum_name(value) for value in header.characteristics_list],
            },
            "optional": {
                "subsystem": _enum_name(optional.subsystem),
                "dll_characteristics": [
                    _enum_name(value) for value in optional.dll_characteristics_lists
                ],
                "magic": _enum_name(optional.magic),
                **{field: getattr(optional, field) for field in (
                    "major_image_version", "minor_image_version",
                    "major_linker_version", "minor_linker_version",
                    "major_operating_system_version", "minor_operating_system_version",
                    "major_subsystem_version", "minor_subsystem_version",
                    "sizeof_code", "sizeof_headers", "sizeof_heap_commit",
                )},
            },
        }

    def process_raw_features(self, raw):
        coff, optional = raw["coff"], raw["optional"]
        hashed = lambda values: FeatureHasher(10, input_type="string").transform([values]).toarray()[0]
        return np.hstack([
            coff["timestamp"], hashed([coff["machine"]]),
            hashed(coff["characteristics"]), hashed([optional["subsystem"]]),
            hashed(optional["dll_characteristics"]), hashed([optional["magic"]]),
            *[optional[field] for field in (
                "major_image_version", "minor_image_version",
                "major_linker_version", "minor_linker_version",
                "major_operating_system_version", "minor_operating_system_version",
                "major_subsystem_version", "minor_subsystem_version",
                "sizeof_code", "sizeof_headers", "sizeof_heap_commit",
            )],
        ]).astype(np.float32)


class SectionInfo(FeatureType):
    name, dim = "section", SECTION_DIM

    @staticmethod
    def _properties(section):
        return [_enum_name(value) for value in section.characteristics_lists]

    def raw_features(self, bytez, binary):
        entry = ""
        try:
            section = binary.section_from_rva(binary.entrypoint - binary.imagebase)
            if section is not None:
                entry = section.name
        except Exception:
            pass
        if not entry:
            for section in binary.sections:
                if "MEM_EXECUTE" in self._properties(section):
                    entry = section.name
                    break
        return {"entry": entry, "sections": [{
            "name": section.name, "size": section.size, "entropy": section.entropy,
            "vsize": section.virtual_size, "props": self._properties(section),
        } for section in binary.sections]}

    def process_raw_features(self, raw):
        sections, entry = raw["sections"], raw["entry"]
        general = [
            len(sections), sum(item["size"] == 0 for item in sections),
            sum(item["name"] == "" for item in sections),
            sum("MEM_READ" in item["props"] and "MEM_EXECUTE" in item["props"] for item in sections),
            sum("MEM_WRITE" in item["props"] for item in sections),
        ]
        pair_hash = lambda field: FeatureHasher(50, input_type="pair").transform(
            [[(item["name"], item[field]) for item in sections]]
        ).toarray()[0]
        string_hash = lambda values: FeatureHasher(50, input_type="string").transform([values]).toarray()[0]
        characteristics = [
            prop for item in sections if item["name"] == entry for prop in item["props"]
        ]
        # Upstream passed the entry string directly as the sample iterable.
        # Modern sklearn rejects that shape, so make the historical per-character
        # tokenization explicit.
        return np.hstack([
            general, pair_hash("size"), pair_hash("entropy"), pair_hash("vsize"),
            string_hash(list(entry)), string_hash(characteristics),
        ]).astype(np.float32)


class ImportsInfo(FeatureType):
    name, dim = "imports", IMPORTS_DIM

    def raw_features(self, bytez, binary):
        imports: dict[str, list[str]] = {}
        for library in binary.imports:
            imports.setdefault(library.name, [])
            for entry in library.entries:
                value = "ordinal" + str(entry.ordinal) if entry.is_ordinal else entry.name[:10000]
                imports[library.name].append(value)
        return imports

    def process_raw_features(self, raw):
        libraries = list(set(library.lower() for library in raw))
        imports = [
            library.lower() + ":" + entry
            for library, entries in raw.items() for entry in entries
        ]
        return np.hstack([
            FeatureHasher(256, input_type="string").transform([libraries]).toarray()[0],
            FeatureHasher(1024, input_type="string").transform([imports]).toarray()[0],
        ]).astype(np.float32)


class ExportsInfo(FeatureType):
    name, dim = "exports", EXPORTS_DIM

    def raw_features(self, bytez, binary):
        return [
            (export.name if hasattr(export, "name") else export)[:10000]
            for export in binary.exported_functions
        ]

    def process_raw_features(self, raw):
        return FeatureHasher(128, input_type="string").transform([raw]).toarray()[0].astype(np.float32)


class DataDirectories(FeatureType):
    name, dim = "datadirectories", DATA_DIRECTORIES_DIM

    def raw_features(self, bytez, binary):
        return [{"size": item.size, "virtual_address": item.rva} for item in binary.data_directories]

    def process_raw_features(self, raw):
        output = np.zeros(30, dtype=np.float32)
        for index, item in enumerate(raw[:15]):
            output[2 * index] = item["size"]
            output[2 * index + 1] = item["virtual_address"]
        return output


class PEFeatureExtractorV2:
    """Compute all official EMBER v2 groups from bytes and one LIEF object."""

    feature_types = (
        ByteHistogram(), ByteEntropyHistogram(), StringExtractor(),
        GeneralFileInfo(), HeaderFileInfo(), SectionInfo(), ImportsInfo(),
        ExportsInfo(), DataDirectories(),
    )
    dim = EMBER_V2_DIM

    def raw_features(self, bytez: bytes, lief_binary: Any) -> dict[str, Any]:
        return {
            feature.name: feature.raw_features(bytez, lief_binary)
            for feature in self.feature_types
        }

    def process_raw_features(
        self, raw: dict[str, Any], timings_ms: dict[str, float] | None = None
    ) -> np.ndarray:
        vectors = []
        for feature in self.feature_types:
            started = perf_counter_ns()
            vector = np.asarray(feature.process_raw_features(raw[feature.name]))
            if vector.shape != (feature.dim,):
                raise FeatureExtractionError(
                    f"{feature.name} must produce {feature.dim} values; got {vector.shape}"
                )
            if timings_ms is not None:
                timings_ms[f"{feature.name}_features_ms"] = (
                    perf_counter_ns() - started
                ) / 1_000_000
            vectors.append(vector)
        output = np.hstack(vectors).astype(np.float32)
        if output.shape != (EMBER_V2_DIM,):
            raise FeatureExtractionError(
                f"EMBER v2 vector must have shape ({EMBER_V2_DIM},); got {output.shape}"
            )
        if output.dtype != np.float32 or not np.isfinite(output).all():
            raise FeatureExtractionError("EMBER v2 vector must be finite float32")
        return output

    def feature_vector(
        self, bytez: bytes, lief_binary: Any, timings_ms: dict[str, float] | None = None
    ) -> np.ndarray:
        try:
            return self.process_raw_features(
                self.raw_features(bytez, lief_binary), timings_ms=timings_ms
            )
        except FeatureExtractionError:
            raise
        except Exception as exc:
            raise FeatureExtractionError(f"EMBER v2 feature extraction failed: {exc}") from exc
