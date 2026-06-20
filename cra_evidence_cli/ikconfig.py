"""
Extract embedded kernel .config from firmware binaries (IKCONFIG).

Kernels compiled with CONFIG_IKCONFIG=y embed the .config as a gzip blob
between the magic markers IKCFG_ST and IKCFG_ED.

Coverage: ~70-85% of OpenWRT/router firmware, ~50-70% of Yocto builds.
Automotive and stripped kernels typically do not embed the config.
"""

import gzip

IKCFG_START = b"IKCFG_ST"
IKCFG_END = b"IKCFG_ED"


def extract_ikconfig(data: bytes) -> bytes | None:
    """Extract the embedded kernel .config from firmware binary data.

    Returns the decompressed .config bytes, or None if not found or
    decompression fails (kernel was not compiled with CONFIG_IKCONFIG=y,
    or config was stripped).
    """
    pos = data.find(IKCFG_START)
    if pos == -1:
        return None
    end = data.find(IKCFG_END, pos)
    if end == -1:
        return None
    try:
        return gzip.decompress(data[pos + len(IKCFG_START):end])
    except Exception:
        return None
