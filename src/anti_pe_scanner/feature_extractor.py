"""PE file to LightGBM feature-vector bridge.

The scanner input is a file path, while the LightGBM model input is exactly
2381 numerical PE features. This module adapts the Anti_PE ((2)) LIEF-based
EMBER-compatible extractor and preserves its feature group order:

1. ByteHistogram[0:256]
2. ByteEntropyHistogram[256:512]
3. StringFeatures[512:616]
4. GeneralFileInfo[616:626]
5. HeaderFileInfo[626:688]
6. SectionInfo[688:943]
7. ImportsInfo[943:2223]
8. ExportsInfo[2223:2351]
9. DataDirectories[2351:2381]

TODO(feature-parity): before production use, compare this extractor against
the old POC extractor on known benign PE files. The same file must produce the
same 2381-vector.
"""

from __future__ import annotations

import hashlib
import math
import re
from pathlib import Path
from time import perf_counter_ns
from typing import Any

import numpy as np
from anti_pe_scanner.prepared_pe import PreparedPEFile, prepare_pe_file

EMBER_FEATURE_DIM = 2381
_MIN_STRING_LEN = 5
_PRINTABLE_STRINGS_RE = re.compile(rb"[ -~]{5,}")
_URL_RE = re.compile(rb"https?://")
_REGISTRY_RE = re.compile(rb"HKEY_|SOFTWARE\\|SYSTEM\\")
_WINDOWS_PATH_RE = re.compile(rb"[Cc]:\\|[Ss]ystem32")
_MZ_RE = re.compile(rb"MZ")
_KNOWN_SECTION_INDEX = {
    name: index
    for index, name in enumerate(
        [
            ".text", ".data", ".rdata", ".rsrc", ".reloc", ".bss",
            ".idata", ".edata", ".pdata", ".xdata", ".tls", ".sxdata",
            "UPX0", "UPX1", "UPX2", ".themida", ".vmp0", ".vmp1",
        ]
    )
}


class FeatureExtractionError(ValueError):
    """Raised when a file cannot be converted into model-ready features."""


def extract_pe_features(file_path: str | Path) -> np.ndarray:
    """Extract a model-ready feature matrix of shape `(1, 2381)`.

    Non-PE files should be filtered by `pe_validator.py` first. This function
    does not create fake or zero vectors for invalid files; extraction failures
    are surfaced as clear exceptions so invalid files never reach inference.
    """
    return PEFeatureExtractor().extract_from_file(file_path)


class PEFeatureExtractor:
    """LIEF-based EMBER-compatible PE feature extractor for inference only."""

    def extract_from_file(self, file_path: str | Path) -> np.ndarray:
        try:
            prepared = prepare_pe_file(file_path)
        except FileNotFoundError:
            raise
        except Exception as exc:
            if getattr(exc, "scan_status", None) == "file_not_found":
                raise FileNotFoundError(f"File not found: {file_path}") from exc
            raise FeatureExtractionError(str(exc)) from exc
        return self.extract_prepared(prepared)

    def extract_from_bytes(self, raw_bytes: bytes, source_name: str = "<bytes>") -> np.ndarray:
        if not raw_bytes:
            raise FeatureExtractionError(f"Cannot extract features from empty file: {source_name}")

        try:
            import lief  # type: ignore

            try:
                lief.logging.disable()
            except Exception:
                pass
        except ImportError as exc:
            raise FeatureExtractionError(
                "LIEF is required for PE feature extraction. Install dependency 'lief'."
            ) from exc

        try:
            lief_binary = lief.PE.parse(raw_bytes)
        except Exception as exc:
            raise FeatureExtractionError(f"LIEF failed to parse PE file {source_name}: {exc}") from exc

        if lief_binary is None:
            raise FeatureExtractionError(f"LIEF failed to parse PE file {source_name}")

        features = _PEFeatureExtractor(raw_bytes, lief_binary).feature_vector()
        return _validate_feature_vector(features)

    def extract_prepared(
        self,
        prepared: PreparedPEFile,
        timings_ms: dict[str, float] | None = None,
    ) -> np.ndarray:
        features = _PEFeatureExtractor(
            prepared.raw_bytes, prepared.lief_binary, timings_ms=timings_ms
        ).feature_vector()
        return _validate_feature_vector(features)


def _validate_feature_vector(features: Any) -> np.ndarray:
    """Return a clean `(1, 2381)` numeric feature matrix or raise ValueError."""
    array = np.asarray(features, dtype=np.float32)

    if array.shape == (EMBER_FEATURE_DIM,):
        array = array.reshape(1, EMBER_FEATURE_DIM)
    elif array.shape != (1, EMBER_FEATURE_DIM):
        raise ValueError(
            f"Feature vector must have shape ({EMBER_FEATURE_DIM},) or "
            f"(1, {EMBER_FEATURE_DIM}); got {array.shape}"
        )

    if not np.isfinite(array).all():
        raise ValueError("Feature vector contains NaN or infinite values")

    return array


class _PEFeatureExtractor:
    """Internal extractor modelled after Anti_PE ((2)) EMBER v2 feature order."""

    def __init__(
        self,
        raw_bytes: bytes,
        lief_binary: Any,
        timings_ms: dict[str, float] | None = None,
    ) -> None:
        self.raw_bytes = raw_bytes
        self.lief = lief_binary
        self.timings_ms = timings_ms
        self.sections = list(getattr(lief_binary, "sections", []))
        self.imports = list(getattr(lief_binary, "imports", []))

    def feature_vector(self) -> np.ndarray:
        groups = [
            ("byte_histogram_ms", self._byte_histogram),
            ("byte_entropy_histogram_ms", self._byte_entropy_histogram),
            ("string_features_ms", self._string_features),
            ("general_features_ms", self._general_file_info),
            ("header_features_ms", self._header_file_info),
            ("section_features_ms", self._section_info),
            ("import_features_ms", self._imports_info),
            ("export_features_ms", self._exports_info),
            ("data_directory_features_ms", self._data_directory_info),
        ]
        parts = []
        for timing_name, function in groups:
            start = perf_counter_ns()
            parts.append(function())
            if self.timings_ms is not None:
                self.timings_ms[timing_name] = (perf_counter_ns() - start) / 1_000_000.0
        vec = np.concatenate(parts)
        if len(vec) < EMBER_FEATURE_DIM:
            vec = np.concatenate([vec, np.zeros(EMBER_FEATURE_DIM - len(vec), dtype=np.float32)])
        elif len(vec) > EMBER_FEATURE_DIM:
            vec = vec[:EMBER_FEATURE_DIM]
        return vec.astype(np.float32)

    def _byte_histogram(self) -> np.ndarray:
        counts = np.zeros(256, dtype=np.int64)
        data = np.frombuffer(self.raw_bytes, dtype=np.uint8)
        # np.bincount may promote the entire input to platform integers
        # internally. Chunking preserves exact counts while bounding peak RAM.
        for start in range(0, len(data), 1024 * 1024):
            counts += np.bincount(data[start : start + 1024 * 1024], minlength=256)
        total = max(counts.sum(), 1)
        return (counts / total).astype(np.float32)

    def _byte_entropy_histogram(self) -> np.ndarray:
        window_size = 2048
        step = 1024
        hist = np.zeros((16, 16), dtype=np.float32)

        data = np.frombuffer(self.raw_bytes, dtype=np.uint8)
        for start in range(0, max(len(data) - window_size + 1, 1), step):
            window = data[start: start + window_size]
            byte_counts = np.bincount(window, minlength=256)
            nonzero = byte_counts[byte_counts > 0]
            probabilities = nonzero / len(window)
            entropy = float(-np.sum(probabilities * np.log2(probabilities)))
            entropy_bin = min(int(entropy / 8.0 * 16), 15)
            coarse_histogram = byte_counts.reshape(16, 16).sum(axis=1)
            hist[entropy_bin] += coarse_histogram / max(coarse_histogram.sum(), 1)

        return (hist / max(hist.sum(), 1)).flatten().astype(np.float32)

    def _string_features(self) -> np.ndarray:
        lengths: list[int] = []
        url_count = registry_count = path_count = mz_count = 0
        for match in _PRINTABLE_STRINGS_RE.finditer(self.raw_bytes):
            start, end = match.span()
            lengths.append(end - start)
            url_count += sum(1 for _ in _URL_RE.finditer(self.raw_bytes, start, end))
            registry_count += sum(
                1 for _ in _REGISTRY_RE.finditer(self.raw_bytes, start, end)
            )
            path_count += sum(
                1 for _ in _WINDOWS_PATH_RE.finditer(self.raw_bytes, start, end)
            )
            mz_count += self.raw_bytes.count(b"MZ", start, end)

        if lengths:
            log_lengths = [math.log2(max(length, 1)) for length in lengths]
            hist, _ = np.histogram(log_lengths, bins=10, range=(0, 10))
        else:
            hist = np.zeros(10, dtype=np.float32)

        scalars = np.array(
            [
                len(lengths),
                float(np.mean(lengths)) if lengths else 0.0,
                url_count,
                registry_count,
                path_count,
                mz_count,
                min(lengths) if lengths else 0,
                max(lengths) if lengths else 0,
                float(np.std(lengths)) if lengths else 0,
                float(np.median(lengths)) if lengths else 0,
            ],
            dtype=np.float32,
        )
        features = np.concatenate([hist.astype(np.float32), scalars])
        return _pad_or_truncate(features, 104)

    def _general_file_info(self) -> np.ndarray:
        file_size = len(self.raw_bytes)
        try:
            sections = self.sections
            virtual_size = sum(getattr(section, "virtual_size", 0) for section in sections)
            return np.array(
                [
                    file_size,
                    virtual_size,
                    len(sections),
                    int(getattr(self.lief, "has_debug", False)),
                    int(getattr(self.lief, "has_tls", False)),
                    int(getattr(self.lief, "has_resources", False)),
                    int(getattr(self.lief, "has_signatures", False)),
                    int(getattr(self.lief, "has_relocations", False)),
                    int(getattr(self.lief, "has_exports", False)),
                    len(self.imports) if getattr(self.lief, "has_imports", False) else 0,
                ],
                dtype=np.float32,
            )
        except Exception:
            return np.array([file_size] + [0] * 9, dtype=np.float32)

    def _header_file_info(self) -> np.ndarray:
        try:
            header = self.lief.header
            optional = self.lief.optional_header
            machine = int(header.machine)
            subsystem = int(optional.subsystem)
            scalars = [
                machine,
                int(header.time_date_stamps),
                int(header.numberof_sections),
                int(header.characteristics),
                subsystem,
                int(optional.dll_characteristics),
                int(optional.magic),
                int(optional.major_linker_version),
                int(optional.minor_linker_version),
                int(optional.sizeof_code),
                int(optional.sizeof_initialized_data),
                int(optional.sizeof_uninitialized_data),
                int(optional.addressof_entrypoint),
                int(optional.imagebase),
                int(optional.section_alignment),
                int(optional.file_alignment),
                int(optional.sizeof_image),
                int(optional.sizeof_headers),
                int(optional.checksum),
                int(optional.major_operating_system_version),
                int(optional.minor_operating_system_version),
                int(optional.major_image_version),
                int(optional.minor_image_version),
                int(optional.major_subsystem_version),
                int(optional.minor_subsystem_version),
            ]
            machines = [0x0, 0x14C, 0x8664, 0x1C0, 0xAA64, 0x200, 0x366]
            subsystems = [0, 1, 2, 3, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
            features = np.array(
                scalars
                + [int(machine == item) for item in machines]
                + [int(subsystem == item) for item in subsystems],
                dtype=np.float32,
            )
        except Exception:
            features = np.zeros(1, dtype=np.float32)
        return _pad_or_truncate(features, 62)

    def _section_info(self) -> np.ndarray:
        try:
            sections = self.sections
        except Exception:
            return np.zeros(255, dtype=np.float32)

        name_presence = np.zeros(len(_KNOWN_SECTION_INDEX), dtype=np.float32)
        entropies = []
        sizes = []
        exec_sections = 0
        writable_sections = 0

        for section in sections:
            section_name = section.name.rstrip("\x00")
            index = _KNOWN_SECTION_INDEX.get(section_name)
            if index is not None:
                name_presence[index] = 1.0

            raw = bytes(section.content)
            entropies.append(_entropy(np.frombuffer(raw, dtype=np.uint8)) if raw else 0.0)
            sizes.append(int(section.size))

            try:
                import lief  # type: ignore

                if lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE in section.characteristics_lists:
                    exec_sections += 1
                if lief.PE.Section.CHARACTERISTICS.MEM_WRITE in section.characteristics_lists:
                    writable_sections += 1
            except Exception:
                pass

        ent_arr = np.array(entropies, dtype=np.float32) if entropies else np.zeros(1)
        size_arr = np.array(sizes, dtype=np.float32) if sizes else np.zeros(1)
        agg = np.array(
            [
                float(len(sections)),
                float(exec_sections),
                float(writable_sections),
                float(np.mean(ent_arr)),
                float(np.max(ent_arr)),
                float(np.min(ent_arr)),
                float(np.std(ent_arr)),
                float(np.mean(size_arr)),
                float(np.max(size_arr)),
                float(np.sum(size_arr)),
            ],
            dtype=np.float32,
        )
        ent_hist, _ = np.histogram(entropies or [0], bins=8, range=(0, 8))
        return _pad_or_truncate(np.concatenate([name_presence, agg, ent_hist.astype(np.float32)]), 255)

    def _imports_info(self) -> np.ndarray:
        if not getattr(self.lief, "has_imports", False):
            return np.zeros(1280, dtype=np.float32)

        try:
            dll_names: list[str] = []
            api_names: list[str] = []
            for imported_library in self.imports:
                dll_names.append(imported_library.name.lower())
                for entry in imported_library.entries:
                    if entry.name:
                        api_names.append(entry.name.lower())

            suspicious_apis = [
                "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
                "NtCreateThread", "RtlCreateUserThread", "ShellExecuteA",
                "ShellExecuteW", "WinExec", "CreateProcessA", "CreateProcessW",
                "URLDownloadToFile", "InternetOpenUrl", "RegSetValueEx",
                "CreateService", "OpenSCManager", "CryptEncrypt", "CryptDecrypt",
                "LoadLibrary", "GetProcAddress", "SetWindowsHookEx",
            ]
            common_dlls = [
                "kernel32.dll", "user32.dll", "advapi32.dll", "ntdll.dll",
                "msvcrt.dll", "ws2_32.dll", "wininet.dll", "urlmon.dll",
                "shell32.dll", "ole32.dll", "oleaut32.dll", "comctl32.dll",
            ]
            features = np.concatenate(
                [
                    _hash_encode(dll_names, 512),
                    _hash_encode(api_names, 512),
                    np.array(
                        [
                            1.0 if any(api.lower() in name for name in api_names) else 0.0
                            for api in suspicious_apis
                        ],
                        dtype=np.float32,
                    ),
                    np.array([1.0 if dll in dll_names else 0.0 for dll in common_dlls], dtype=np.float32),
                    np.array([float(len(dll_names)), float(len(api_names))], dtype=np.float32),
                ]
            )
        except Exception:
            return np.zeros(1280, dtype=np.float32)
        return _pad_or_truncate(features, 1280)

    def _exports_info(self) -> np.ndarray:
        if not getattr(self.lief, "has_exports", False):
            return np.zeros(128, dtype=np.float32)

        try:
            export_names = [entry.name for entry in self.lief.exports.entries if entry.name]
            features = np.concatenate(
                [
                    _hash_encode(export_names, 120),
                    np.array([float(len(export_names)), float(min(len(export_names), 100))], dtype=np.float32),
                ]
            )
        except Exception:
            return np.zeros(128, dtype=np.float32)
        return _pad_or_truncate(features, 128)

    def _data_directory_info(self) -> np.ndarray:
        try:
            values = []
            for data_directory in self.lief.data_directories:
                values.extend([float(data_directory.size), float(int(data_directory.size > 0))])
            features = np.array(values[:72], dtype=np.float32)
        except Exception:
            return np.zeros(72, dtype=np.float32)
        return _pad_or_truncate(features, 72)


def _entropy(data: np.ndarray) -> float:
    if len(data) == 0:
        return 0.0
    counts = np.bincount(data, minlength=256)
    probs = counts[counts > 0] / len(data)
    return float(-np.sum(probs * np.log2(probs)))


def _extract_printable_strings(data: bytes, min_length: int = 5) -> list[bytes]:
    pattern = rb"[ -~]{" + str(min_length).encode() + rb",}"
    return re.findall(pattern, data)


def _hash_encode(names: list[str], n_features: int = 512) -> np.ndarray:
    vec = np.zeros(n_features, dtype=np.float32)
    for name in names:
        digest = hashlib.sha256(name.lower().encode("utf-8", errors="ignore")).digest()
        vec[int.from_bytes(digest, "big") % n_features] = 1.0
    return vec


def _pad_or_truncate(features: np.ndarray, target: int) -> np.ndarray:
    if len(features) < target:
        features = np.concatenate([features, np.zeros(target - len(features), dtype=np.float32)])
    return features[:target].astype(np.float32)


def get_feature_group_names() -> list[str]:
    return [
        "ByteHistogram[0:256]",
        "ByteEntropyHistogram[256:512]",
        "StringFeatures[512:616]",
        "GeneralFileInfo[616:626]",
        "HeaderFileInfo[626:688]",
        "SectionInfo[688:943]",
        "ImportsInfo[943:2223]",
        "ExportsInfo[2223:2351]",
        "DataDirectories[2351:2381]",
    ]
