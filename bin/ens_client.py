#! /usr/bin/python3
# (c) Copyright 2022-2026, James Stevens ... see LICENSE for details
# Alternative license arrangements possible, contact me for more information
"""On-chain ENS lookups over Ethereum JSON-RPC.

The gateway asks the ENS registry for a resolver, then reads ``addr``,
``name``, ``contenthash`` or ``dnsRecord``. When the resolver supports
ENSIP-10 ``resolve(bytes,bytes)``, including a parent wildcard resolver,
that call is used instead.

EIP-3668 CCIP-Read is not implemented. A revert whose data starts with
``OffchainLookup`` is an empty answer, as is any other execution revert.
"""

import os
import threading
import unicodedata
from urllib.parse import urlsplit, urlunsplit

import requests

try:
    from Crypto.Hash import keccak as _keccak
except ImportError:  # Debian/Ubuntu package the same library as Cryptodome
    from Cryptodome.Hash import keccak as _keccak

import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype

ENS_REGISTRY = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"
ALCHEMY_MAINNET_HOST = "eth-mainnet.g.alchemy.com"
# Keyless Ethereum mainnet JSON-RPC. Checked with eth_chainId and an ENS eth_call.
PUBLIC_MAINNET_RPC = "https://ethereum.publicnode.com"

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_CONTENT_CODECS = {
    0xE3: "ipfs-ns",
    0xE4: "swarm-ns",
    0xE5: "ipns-ns",
    444: "onion",
    445: "onion3",
}

_selector_cache = {}
_selector_lock = threading.Lock()


class TransportError(Exception):
    """The JSON-RPC endpoint could not be reached or returned an unusable body."""


class RpcRevert(Exception):
    """``eth_call`` reverted. ``data`` is the raw revert payload, if any."""

    def __init__(self, data):
        super().__init__("execution reverted")
        self.data = data or b""


def keccak256(data):
    digest = _keccak.new(digest_bits=256)
    digest.update(data)
    return digest.digest()


def selector(signature):
    with _selector_lock:
        found = _selector_cache.get(signature)
        if found is None:
            found = keccak256(signature.encode("ascii"))[:4]
            _selector_cache[signature] = found
        return found


OFFCHAIN_LOOKUP = selector(
    "OffchainLookup(address,string[],bytes,bytes4,bytes)")
EXTENDED_RESOLVER = selector("resolve(bytes,bytes)")


def is_offchain_lookup(data):
    return data.startswith(OFFCHAIN_LOOKUP)


def alchemy_mainnet_url(api_key):
    return f"https://{ALCHEMY_MAINNET_HOST}/v2/{api_key}"


def describe_rpc_url(url):
    """Return a URL safe to log. Userinfo, query, and /v2 or /v3 keys are hidden."""
    parts = urlsplit(url.strip())
    segments = []
    hide_next = False
    for segment in parts.path.split("/"):
        if hide_next and segment:
            segments.append("***")
            hide_next = False
            continue
        segments.append(segment)
        if segment in ("v2", "v3"):
            hide_next = True
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, host, "/".join(segments), "", ""))


def select_rpc_endpoint(environ):
    """Pick the JSON-RPC URL.

    ``ETH_RPC_URL`` wins, then Alchemy when ``ALCHEMY_API_CODE`` is set,
    otherwise the public mainnet endpoint. The second value is safe to log.
    """
    override = environ.get("ETH_RPC_URL", "").strip()
    if override:
        return override, "ETH_RPC_URL " + describe_rpc_url(override)
    api_key = environ.get("ALCHEMY_API_CODE", "").strip()
    if api_key:
        return (alchemy_mainnet_url(api_key),
                f"Alchemy https://{ALCHEMY_MAINNET_HOST}/v2/***")
    return PUBLIC_MAINNET_RPC, "public default " + PUBLIC_MAINNET_RPC


def _label_to_unicode(label):
    """Decode one label. ``xn--`` uses the ``punycode`` codec, not IDNA rules.

    IDNA rejects emoji labels that ENS accepts. A failed punycode decode
    returns ``None`` so the lookup becomes an empty DNS answer.
    """
    if label.lower().startswith("xn--"):
        try:
            decoded = label.lower()[4:].encode("ascii").decode("punycode")
        except UnicodeError:
            return None
    else:
        decoded = label
    normalized = unicodedata.normalize("NFC", decoded).lower()
    if not normalized or "." in normalized or "\x00" in normalized:
        return None
    return normalized


def normalize_name(name):
    """Unicode ENS name: punycode decoded, NFC, lowercased.

    Raises ``ValueError`` when a ``xn--`` label is not valid punycode.
    """
    text = name.strip()
    text = text.removesuffix(".")
    if text == "":
        return ""
    labels = []
    for label in text.split("."):
        decoded = _label_to_unicode(label)
        if decoded is None:
            raise ValueError("invalid ens label")
        labels.append(decoded)
    return ".".join(labels)


def to_puny(name):
    """Encode non-ASCII labels as ``xn--`` punycode for a DNS answer.

    Returns ``None`` when ``name`` contains punycode that will not decode.
    ASCII labels are left as normalized text. This is the lenient per-label
    counterpart of encoding a name back onto the wire.
    """
    if name is None:
        return None
    stripped = name.strip()
    if stripped in ("", "."):
        return stripped
    try:
        normalized = normalize_name(stripped)
    except ValueError:
        return None
    if normalized == "":
        return ""
    encoded = []
    for label in normalized.split("."):
        if label.isascii():
            encoded.append(label)
            continue
        try:
            encoded.append("xn--" + label.encode("punycode").decode("ascii"))
        except UnicodeError:
            return None
    return ".".join(encoded)


def namehash(name):
    """EIP-137 namehash of the normalized Unicode name. No ENSIP-15 tables."""
    node = bytes(32)
    normalized = normalize_name(name)
    if not normalized:
        return node
    for label in reversed(normalized.split(".")):
        node = keccak256(node + keccak256(label.encode("utf-8")))
    return node


def dns_encode(name):
    """DNS wire encoding of an ENS name, including the root label."""
    normalized = normalize_name(name)
    if not normalized:
        return b"\x00"
    out = bytearray()
    for label in normalized.split("."):
        raw = label.encode("utf-8")
        if not raw or len(raw) > 255:
            raise ValueError("bad dns label")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    if len(out) > 255:
        raise ValueError("dns name is too long")
    return bytes(out)


def checksum_address(raw):
    hexed = raw.hex()
    hashed = keccak256(hexed.encode("ascii")).hex()
    chars = []
    for char, nybble in zip(hexed, hashed):
        if char.isalpha() and int(nybble, 16) >= 8:
            chars.append(char.upper())
        else:
            chars.append(char)
    return "0x" + "".join(chars)


def normalize_address(value):
    text = value.strip().lower()
    text = text.removeprefix("0x")
    if len(text) != 40:
        return None
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        return None
    return checksum_address(raw)


def encode_dynamic_blob(payload):
    pad = (-len(payload)) % 32
    return len(payload).to_bytes(32, "big") + payload + bytes(pad)


def encode_static_words(signature, words):
    body = bytearray()
    for word in words:
        if len(word) > 32:
            raise ValueError("abi word is longer than 32 bytes")
        body.extend(word.rjust(32, b"\x00"))
    return selector(signature) + bytes(body)


def encode_bytes_args(selector_bytes, blobs):
    """ABI-encode a call whose arguments are all dynamic ``bytes``."""
    head_len = 32 * len(blobs)
    parts = []
    offsets = []
    cursor = head_len
    for blob in blobs:
        offsets.append(cursor)
        encoded = encode_dynamic_blob(blob)
        parts.append(encoded)
        cursor += len(encoded)
    head = b"".join(offset.to_bytes(32, "big") for offset in offsets)
    return selector_bytes + head + b"".join(parts)


def encode_supports_interface(interface_id):
    if len(interface_id) != 4:
        raise ValueError("interface id must be 4 bytes")
    return selector("supportsInterface(bytes4)") + interface_id.ljust(
        32, b"\x00")


def abi_encode_bytes(payload):
    """ABI encoding of a single ``bytes`` or ``string`` return value."""
    return (32).to_bytes(32, "big") + encode_dynamic_blob(payload)


def decode_word(data, index=0):
    start = index * 32
    end = start + 32
    if end > len(data):
        raise ValueError("abi word is out of range")
    return data[start:end]


def decode_bool(data):
    if data is None or len(data) < 32:
        return False
    return int.from_bytes(decode_word(data, 0), "big") != 0


def decode_address(data):
    if data is None or len(data) < 32:
        return None
    raw = decode_word(data, 0)[12:]
    if raw == bytes(20):
        return None
    return checksum_address(raw)


def decode_bytes(data):
    if len(data) < 64:
        raise ValueError("abi bytes value is too short")
    offset = int.from_bytes(data[:32], "big")
    if offset + 32 > len(data):
        raise ValueError("abi bytes offset is out of range")
    length = int.from_bytes(data[offset:offset + 32], "big")
    start = offset + 32
    end = start + length
    if end > len(data):
        raise ValueError("abi bytes value is truncated")
    return data[start:end]


def decode_string(data):
    return decode_bytes(data).decode("utf-8")


def read_uvarint(data, offset):
    value = 0
    shift = 0
    while True:
        if offset >= len(data):
            raise ValueError("truncated varint")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7
        if shift > 63:
            raise ValueError("varint is too long")


def b58encode(data):
    zeros = 0
    for byte in data:
        if byte == 0:
            zeros += 1
        else:
            break
    number = int.from_bytes(data, "big")
    chars = []
    while number:
        number, rem = divmod(number, 58)
        chars.append(_B58_ALPHABET[rem])
    return ("1" * zeros) + "".join(reversed(chars))


def _take_multihash(data, offset):
    start = offset
    _code, offset = read_uvarint(data, offset)
    length, offset = read_uvarint(data, offset)
    end = offset + length
    if length < 0 or end != len(data):
        return None
    return data[start:end]


def _multihash_from_cidv1(data):
    if not data or data[0] != 0x01:
        return None
    try:
        offset = 0
        version, offset = read_uvarint(data, offset)
        if version != 1:
            return None
        _codec, offset = read_uvarint(data, offset)
    except ValueError:
        return None
    return _take_multihash(data, offset)


def multihash_bytes(cid_bytes):
    """Return the multihash inside a contenthash value.

    The usual ENS encoding is a CIDv1 (``01 <codec> <multihash>``). Some
    records still use the older ``cids`` buffer that prefixes that with an
    extra ``01`` byte. A bare multihash is accepted too.
    """
    found = _multihash_from_cidv1(cid_bytes)
    if found is not None:
        return found
    if len(cid_bytes) >= 3 and cid_bytes[0] == 0x01 and cid_bytes[1] == 0x01:
        found = _multihash_from_cidv1(cid_bytes[1:])
        if found is not None:
            return found
    found = _take_multihash(cid_bytes, 0)
    if found is not None:
        return found
    raise ValueError("unrecognised CID")


def multihash_digest(cid_bytes):
    multihash = multihash_bytes(cid_bytes)
    offset = 0
    _code, offset = read_uvarint(multihash, offset)
    length, offset = read_uvarint(multihash, offset)
    return multihash[offset:offset + length]


def decode_contenthash(data):
    """Decode an ENS contenthash the way the ``content-hash`` package did.

    IPFS and IPNS values are the base58btc multihash (a CIDv0 ``Qm...`` string
    for the common dag-pb + sha2-256 case). Returns ``None`` when ``data`` is
    empty or the outer multicodec is not one this gateway knows.
    """
    if isinstance(data, str):
        text = data.removeprefix("0x")
        data = bytes.fromhex(text)
    if not data:
        return None
    code, offset = read_uvarint(data, 0)
    codec = _CONTENT_CODECS.get(code)
    if codec is None:
        return None
    value = data[offset:]
    if codec in ("ipfs-ns", "ipns-ns"):
        return {"codec": codec, "value": b58encode(multihash_bytes(value))}
    if codec == "swarm-ns":
        try:
            decoded = multihash_digest(value).hex()
        except ValueError:
            decoded = value.hex()
        return {"codec": codec, "value": decoded}
    return {"codec": codec, "value": value.decode("utf-8")}


def _error_payload(error):
    data = error.get("data") if isinstance(error, dict) else None
    if isinstance(data, dict):
        data = data.get("data")
    if not isinstance(data, str) or not data.startswith("0x"):
        return b""
    hexdata = data[2:]
    if len(hexdata) % 2:
        hexdata = "0" + hexdata
    try:
        return bytes.fromhex(hexdata)
    except ValueError:
        return b""


def parse_rpc_result(body):
    """Return ``eth_call`` bytes, or ``None`` for an empty result or a revert.

    Any other JSON-RPC error is a ``TransportError`` so the DNS query is
    dropped instead of published as an empty answer.
    """
    if not isinstance(body, dict):
        raise TransportError("rpc response is not an object")
    if "error" in body and body.get("result") in (None, "0x"):
        error = body["error"] if isinstance(body["error"], dict) else {}
        message = str(error.get("message") or "")
        payload = _error_payload(error)
        reverted = error.get("code") == 3 or "revert" in message.lower(
        ) or is_offchain_lookup(payload)
        if not reverted:
            raise TransportError(message or "rpc error")
        return None
    result = body.get("result")
    if not isinstance(result, str) or not result.startswith("0x"):
        return None
    hexdata = result[2:]
    if len(hexdata) % 2:
        hexdata = "0" + hexdata
    if hexdata == "":
        return None
    try:
        return bytes.fromhex(hexdata)
    except ValueError as exc:
        raise TransportError("rpc result is not hex") from exc


def _puny_name_text(name):
    text = name.to_text()
    absolute = text == "." or text.endswith(".")
    if text != "." and text.endswith("."):
        text = text[:-1]
    puny = to_puny(text)
    if puny is None:
        raise ValueError("invalid dns name")
    if puny == ".":
        return "."
    return puny + "." if absolute else puny


def _rdata_text(rdata):
    """Presentation text, with domain names written as punycode labels."""
    kind = dns.rdatatype.to_text(rdata.rdtype)
    if kind in ("CNAME", "NS", "PTR", "DNAME") and hasattr(rdata, "target"):
        return _puny_name_text(rdata.target)
    if kind == "MX" and hasattr(rdata, "exchange"):
        return f"{int(rdata.preference)} {_puny_name_text(rdata.exchange)}"
    if kind == "SRV" and hasattr(rdata, "target"):
        return f"{int(rdata.priority)} {int(rdata.weight)} {int(rdata.port)} {_puny_name_text(rdata.target)}"
    if kind == "SOA" and hasattr(rdata, "mname"):
        timers = f"{int(rdata.serial)} {int(rdata.refresh)} {int(rdata.retry)} {int(rdata.expire)} {int(rdata.minimum)}"
        return f"{_puny_name_text(rdata.mname)} {_puny_name_text(rdata.rname)} {timers}"
    return rdata.to_text()


def parse_wire_rrs(wire):
    """Decode one or more uncompressed or compressed DNS resource records."""
    records = []
    offset = 0
    while offset < len(wire):
        name, consumed = dns.name.from_wire(wire, offset)
        if consumed <= 0:
            raise ValueError("dns name did not advance")
        offset += consumed
        if offset + 10 > len(wire):
            raise ValueError("truncated dns record")
        rtype = int.from_bytes(wire[offset:offset + 2], "big")
        rclass = int.from_bytes(wire[offset + 2:offset + 4], "big")
        ttl = int.from_bytes(wire[offset + 4:offset + 8], "big")
        rdlen = int.from_bytes(wire[offset + 8:offset + 10], "big")
        offset += 10
        if offset + rdlen > len(wire):
            raise ValueError("truncated dns rdata")
        rdata = dns.rdata.from_wire(rclass, rtype, wire, offset, rdlen)
        offset += rdlen
        owner = name.to_text()
        if owner != "." and owner.endswith("."):
            owner = owner[:-1]
        owner = to_puny(owner)
        if owner is None:
            raise ValueError("invalid dns name")
        records.append({
            "name": owner,
            "ttl": ttl,
            "class": dns.rdataclass.to_text(rclass),
            "type": dns.rdatatype.to_text(rtype),
            "data": _rdata_text(rdata),
        })
    return records


class EnsClient:
    """Resolve ENS records through ``eth_call``."""

    def __init__(self, api_key=None, url=None, caller=None, timeout=10):
        self._caller = caller
        self.timeout = timeout
        self.request_id = 0
        self._extended = {}
        self._session = None
        self.url = url
        if caller is not None:
            return
        if not url:
            if api_key:
                url = alchemy_mainnet_url(api_key)
            else:
                url, _label = select_rpc_endpoint(os.environ)
        self.url = url
        self._session = requests.Session()
        self._session.headers["Content-Type"] = "application/json"
        self._session.headers["User-Agent"] = "ethereum-dns-gateway"

    def eth_address(self, name):
        try:
            node = namehash(name)
        except ValueError:
            return None
        raw = self._resolve(name, encode_static_words("addr(bytes32)", [node]))
        return decode_address(raw)

    def content(self, name):
        try:
            node = namehash(name)
        except ValueError:
            return None
        raw = self._resolve(
            name, encode_static_words("contenthash(bytes32)", [node]))
        if not raw:
            return None
        try:
            blob = decode_bytes(raw)
        except ValueError:
            return None
        if not blob:
            return None
        try:
            return decode_contenthash(blob)
        except (ValueError, UnicodeDecodeError):
            return None

    def primary_name(self, address):
        """Reverse record for ``address``, kept only when forward resolution matches.

        This is the check ethers performs: ``name()`` on
        ``<address>.addr.reverse``, then ``addr()`` on that name.
        """
        checksum = normalize_address(address)
        if checksum is None:
            return None
        reverse_name = checksum[2:].lower() + ".addr.reverse"
        try:
            node = namehash(reverse_name)
        except ValueError:
            return None
        raw = self._resolve(reverse_name,
                            encode_static_words("name(bytes32)", [node]))
        if not raw:
            return None
        try:
            primary = decode_string(raw)
        except (ValueError, UnicodeDecodeError):
            return None
        if not primary:
            return None
        forward = self.eth_address(primary)
        if forward is None or forward.lower() != checksum.lower():
            return None
        return primary

    def dns_records(self, name, rrtype):
        """ENSIP-6 ``dnsRecord`` for ``name`` and a DNS type such as ``\"A\"``."""
        try:
            node = namehash(name)
            wire_name = dns_encode(name)
            type_id = int(dns.rdatatype.from_text(rrtype)) if isinstance(
                rrtype, str) else int(rrtype)
        except (ValueError, dns.rdatatype.UnknownRdatatype):
            return None
        calldata = encode_static_words(
            "dnsRecord(bytes32,bytes32,uint16)",
            [node, keccak256(wire_name),
             type_id.to_bytes(2, "big")],
        )
        raw = self._resolve(name, calldata)
        if not raw:
            return None
        try:
            blob = decode_bytes(raw)
        except ValueError:
            return None
        if not blob:
            return None
        try:
            records = parse_wire_rrs(blob)
        except (ValueError, dns.exception.DNSException):
            return None
        return records or None

    def _resolve(self, name, calldata):
        resolver = self._find_resolver(name)
        if resolver is None:
            return None
        if self._supports_extended(resolver):
            try:
                packet = encode_bytes_args(EXTENDED_RESOLVER,
                                           [dns_encode(name), calldata])
            except ValueError:
                return None
            outer = self._eth_call(resolver, packet)
            if not outer:
                return None
            try:
                return decode_bytes(outer)
            except ValueError:
                return None
        return self._eth_call(resolver, calldata)

    def _find_resolver(self, name):
        try:
            original = normalize_name(name)
        except ValueError:
            return None
        current = original
        while current:
            # The eth node has no wildcard resolver. ethers skips it.
            if original != "eth" and current == "eth":
                return None
            addr = self._resolver_of(current)
            if addr is not None:
                if current != original and not self._supports_extended(addr):
                    return None
                return addr
            if "." not in current:
                return None
            current = current.split(".", 1)[1]
        return None

    def _resolver_of(self, name):
        raw = self._eth_call(
            ENS_REGISTRY,
            encode_static_words("resolver(bytes32)", [namehash(name)]))
        return decode_address(raw)

    def _supports_extended(self, resolver):
        key = resolver.lower()
        cached = self._extended.get(key)
        if cached is not None:
            return cached
        raw = self._eth_call(resolver,
                             encode_supports_interface(EXTENDED_RESOLVER))
        supported = decode_bool(raw)
        self._extended[key] = supported
        return supported

    def _eth_call(self, to, data):
        if self._caller is not None:
            try:
                return self._caller(to, data)
            except RpcRevert:
                # Includes OffchainLookup. CCIP-Read is not followed.
                return None
        return self._http_eth_call(to, data)

    def _http_eth_call(self, to, data):
        self.request_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": "eth_call",
            "params": [{
                "to": to,
                "data": "0x" + data.hex()
            }, "latest"],
        }
        try:
            response = self._session.post(self.url,
                                          json=payload,
                                          timeout=self.timeout)
            response.raise_for_status()
            body = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise TransportError(str(exc)) from exc
        return parse_rpc_result(body)
