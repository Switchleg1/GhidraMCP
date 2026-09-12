"""AddressNormalizer — canonical address strings for Ghidra's AddressFactory.

Rules are an ordered table; the first matching pattern wins.

    space:0xHEX / space::0xHEX -> space:HEX / space::HEX   (0x not allowed after ':')
    space:HEX   / space::HEX   -> unchanged                (case-sensitive space names)
    0xHEX / 0XHEX              -> 0xhex
    HEX                        -> 0xhex
"""

from __future__ import annotations

import re
from typing import Callable

_RULES: list[tuple[re.Pattern, Callable[[re.Match], str]]] = [
    (re.compile(r"^([^\s:]+::?)0[xX]([0-9a-fA-F]+)$"), lambda m: f"{m[1]}{m[2]}"),
    (re.compile(r"^[^\s:]+::?[0-9a-fA-F]+$"),          lambda m: m[0]),
    (re.compile(r"^0[xX]([0-9a-fA-F]+)$"),              lambda m: f"0x{m[1].lower()}"),
    (re.compile(r"^([0-9a-fA-F]+)$"),                   lambda m: f"0x{m[1].lower()}"),
]


class AddressNormalizer:
    @staticmethod
    def normalize(address) -> str:
        if address is None:
            return address
        s = str(address).strip()
        for pattern, transform in _RULES:
            m = pattern.match(s)
            if m:
                return transform(m)
        return s          # unknown form: let Ghidra report it
