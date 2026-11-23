#! /usr/bin/python3
"""Unit tests for ENS namehash, ABI coding, contenthash and the DNS gateway."""

import io
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bin"))

import dns.message
import dns.name
import dns.rdata
import dns.rdatatype
import dns.rrset
import ens_client
from ens_client import (
    ENS_REGISTRY,
    EXTENDED_RESOLVER,
    OFFCHAIN_LOOKUP,
    PUBLIC_MAINNET_RPC,
    EnsClient,
    RpcRevert,
    TransportError,
    abi_encode_bytes,
    alchemy_mainnet_url,
    b58encode,
    checksum_address,
    decode_address,
    decode_bytes,
    decode_contenthash,
    decode_string,
    dns_encode,
    encode_bytes_args,
    encode_static_words,
    encode_supports_interface,
    is_offchain_lookup,
    namehash,
    normalize_name,
    parse_rpc_result,
    parse_wire_rrs,
    select_rpc_endpoint,
    selector,
    to_puny,
)
from eth_redirect import answer_rrsets, fill_reply

VITALIK = "0xee6c4522aab0003e8d14cd40a6af439055fd2577951148c14b6cea9a53475835"
VITALIK_ADDRESS = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
# ipfs-ns varint (0xe3 -> e3 01) followed by a CIDv1 dag-pb sha2-256.
CONTENT_LEGACY = (
    "e3010170122029f2d17be6139079dc48696d1f582a8530eb9805b561eda517e22a892c7e3f1f"
)
CONTENT_QM = "QmRAQB6YaCyidP37UdDnjFY5vQuiBrcqdyoW1CuDgwxkD4"
RESOLVER = "0x231b0Ee14048e9dCcD1d247744d114a4EB5E8E63"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "bitsofcode_eth.json"


def word_address(address):
    raw = bytes.fromhex(address[2:])
    return bytes(12) + raw


class Script:

    def __init__(self):
        self.map = {}
        self.seen = []

    def add(self, to, data, result):
        self.map[(to.lower(), data.hex())] = result
        return self

    def __call__(self, to, data):
        self.seen.append(data[:4].hex())
        item = self.map.get((to.lower(), data.hex()))
        if item is None and (to.lower(), data.hex()) not in self.map:
            raise AssertionError(
                f"unexpected call {to} {data[:4].hex()} {data.hex()}")
        if isinstance(item, Exception):
            raise item
        return item


def registry(name, address):
    data = encode_static_words("resolver(bytes32)", [namehash(name)])
    if address is None:
        return ENS_REGISTRY, data, bytes(32)
    return ENS_REGISTRY, data, word_address(address)


def supports(resolver, enabled):
    data = encode_supports_interface(EXTENDED_RESOLVER)
    word = (b"\x01" if enabled else b"\x00").rjust(32, b"\x00")
    return resolver, data, word


def direct(resolver, signature, node, result):
    data = encode_static_words(signature, [node])
    return resolver, data, result


class NamehashAbiContentTests(unittest.TestCase):

    def test_namehash_vectors(self):
        self.assertEqual(namehash(""), bytes(32))
        self.assertEqual(namehash("."), bytes(32))
        self.assertEqual(
            namehash("eth").hex(),
            "93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae",
        )
        self.assertEqual(
            namehash("foo.eth").hex(),
            "de9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f",
        )
        self.assertEqual(namehash("vitalik.eth").hex(), VITALIK[2:])
        self.assertEqual(namehash("Vitalik.ETH"), namehash("vitalik.eth"))

    def test_empty_label_rejected(self):
        with self.assertRaises(ValueError):
            namehash("foo..eth")

    def test_emoji_punycode_round_trip_and_namehash(self):
        emoji = "💩"
        unicode_name = emoji + ".eth"
        puny = "xn--ls8h.eth"
        # Independent of normalize_name: hash the Unicode label bytes directly.
        expected = ens_client.keccak256(
            namehash("eth") + ens_client.keccak256(emoji.encode("utf-8")))
        self.assertEqual(
            expected.hex(),
            "3aef7cc933c5fb65036d4ddd389fdf5c65b1fc79e9c1f34655c86e373d974d76")
        self.assertEqual(normalize_name(puny), unicode_name)
        self.assertEqual(normalize_name("XN--LS8H.ETH"), unicode_name)
        self.assertEqual(to_puny(unicode_name), puny)
        self.assertEqual(to_puny(puny), puny)
        self.assertEqual(namehash(puny), expected)
        self.assertEqual(namehash(unicode_name), expected)
        self.assertEqual(
            dns_encode(puny),
            bytes([len(emoji.encode("utf-8"))]) + emoji.encode("utf-8") +
            b"\x03eth\x00",
        )
        # NFC then lowercase, so the punycode of U+00C9 matches U+00E9.
        self.assertEqual(namehash("xn--dca.eth"), namehash("é.eth"))
        self.assertEqual(namehash("É.eth"), namehash("é.eth"))
        self.assertEqual(to_puny("É.eth"), "xn--9ca.eth")
        self.assertEqual(normalize_name("e\u0301.eth"), "é.eth")

    def test_invalid_punycode_is_rejected(self):
        with self.assertRaises(ValueError):
            namehash("xn--???.eth")
        self.assertIsNone(to_puny("xn--???.eth"))

    def test_dns_encode(self):
        self.assertEqual(dns_encode("vitalik.eth"),
                         bytes.fromhex("07766974616c696b0365746800"))
        self.assertEqual(dns_encode("name.eth"),
                         bytes.fromhex("046e616d650365746800"))

    def test_selectors(self):
        self.assertEqual(selector("resolver(bytes32)"),
                         bytes.fromhex("0178b8bf"))
        self.assertEqual(selector("addr(bytes32)"), bytes.fromhex("3b3b57de"))
        self.assertEqual(selector("name(bytes32)"), bytes.fromhex("691f3431"))
        self.assertEqual(selector("contenthash(bytes32)"),
                         bytes.fromhex("bc1c58d1"))
        self.assertEqual(selector("supportsInterface(bytes4)"),
                         bytes.fromhex("01ffc9a7"))
        self.assertEqual(selector("resolve(bytes,bytes)"),
                         bytes.fromhex("9061b923"))
        self.assertEqual(OFFCHAIN_LOOKUP, bytes.fromhex("556f1830"))
        self.assertTrue(is_offchain_lookup(OFFCHAIN_LOOKUP + b"\x00\x01"))
        self.assertFalse(is_offchain_lookup(b"\x11\x22\x33\x44"))

    def test_addr_call_and_resolve_layout(self):
        node = namehash("vitalik.eth")
        call = encode_static_words("addr(bytes32)", [node])
        self.assertEqual(call[:4], bytes.fromhex("3b3b57de"))
        self.assertEqual(call[4:], node)

        dns_name = dns_encode("vitalik.eth")
        encoded = encode_bytes_args(selector("resolve(bytes,bytes)"),
                                    [dns_name, call])
        self.assertEqual(encoded[:4], bytes.fromhex("9061b923"))
        self.assertEqual(int.from_bytes(encoded[4:36], "big"), 64)
        pad = (-len(dns_name)) % 32
        second = 64 + 32 + len(dns_name) + pad
        self.assertEqual(int.from_bytes(encoded[36:68], "big"), second)
        self.assertEqual(int.from_bytes(encoded[68:100], "big"), len(dns_name))
        self.assertEqual(encoded[100:100 + len(dns_name)], dns_name)

    def test_abi_address_and_string_round_trip(self):
        raw = bytes.fromhex(VITALIK_ADDRESS[2:])
        self.assertEqual(decode_address(bytes(12) + raw), VITALIK_ADDRESS)
        self.assertIsNone(decode_address(bytes(32)))
        self.assertEqual(checksum_address(raw), VITALIK_ADDRESS)

        text = b"bitsofcode.eth"
        encoded = abi_encode_bytes(text)
        self.assertEqual(decode_bytes(encoded), text)
        self.assertEqual(decode_string(encoded), "bitsofcode.eth")
        wrapped = abi_encode_bytes(bytes(12) + raw)
        self.assertEqual(decode_address(decode_bytes(wrapped)),
                         VITALIK_ADDRESS)

    def test_supports_interface_is_right_padded(self):
        data = encode_supports_interface(EXTENDED_RESOLVER)
        self.assertEqual(data[:4], bytes.fromhex("01ffc9a7"))
        self.assertEqual(data[4:8], EXTENDED_RESOLVER)
        self.assertEqual(data[8:], bytes(28))

    def test_contenthash_vectors(self):
        decoded = decode_contenthash(CONTENT_LEGACY)
        self.assertEqual(decoded["codec"], "ipfs-ns")
        self.assertEqual(decoded["value"], CONTENT_QM)
        decoded = decode_contenthash("0x" + CONTENT_LEGACY)
        self.assertEqual(decoded["value"], CONTENT_QM)
        self.assertEqual(
            b58encode(
                bytes.fromhex(
                    "122029f2d17be6139079dc48696d1f582a8530eb9805b561eda517e22a892c7e3f1f"
                )), CONTENT_QM)
        self.assertIsNone(decode_contenthash(b""))
        self.assertIsNone(decode_contenthash("0x"))

    def test_alchemy_url_uses_the_current_mainnet_host(self):
        self.assertEqual(
            alchemy_mainnet_url("abc"),
            "https://eth-mainnet.g.alchemy.com/v2/abc",
        )

    def test_rpc_endpoint_precedence(self):
        url, label = select_rpc_endpoint({})
        self.assertEqual(url, PUBLIC_MAINNET_RPC)
        self.assertIn(PUBLIC_MAINNET_RPC, label)

        url, label = select_rpc_endpoint({"ALCHEMY_API_CODE": "secret-key"})
        self.assertEqual(url, alchemy_mainnet_url("secret-key"))
        self.assertNotIn("secret-key", label)
        self.assertIn("eth-mainnet.g.alchemy.com", label)

        url, label = select_rpc_endpoint({
            "ETH_RPC_URL": "https://user:pw@rpc.example/v2/secret-key?x=1",
            "ALCHEMY_API_CODE": "other-key",
        })
        self.assertEqual(url, "https://user:pw@rpc.example/v2/secret-key?x=1")
        self.assertNotIn("secret-key", label)
        self.assertNotIn("other-key", label)
        self.assertNotIn("pw", label)
        self.assertIn("rpc.example", label)
        self.assertIn("***", label)

        self.assertEqual(
            select_rpc_endpoint({
                "ETH_RPC_URL": "  ",
                "ALCHEMY_API_CODE": "  ",
            })[0], PUBLIC_MAINNET_RPC)
        blank = {
            key: os.environ.pop(key, None)
            for key in ("ETH_RPC_URL", "ALCHEMY_API_CODE")
        }
        try:
            client = EnsClient()
            self.assertEqual(client.url, PUBLIC_MAINNET_RPC)
        finally:
            for key, value in blank.items():
                if value is not None:
                    os.environ[key] = value


class ResolverClientTests(unittest.TestCase):

    def client(self, script):
        return EnsClient(caller=script)

    def test_direct_addr_when_resolve_is_unsupported(self):
        node = namehash("vitalik.eth")
        script = Script()
        for to, data, result in (
                registry("vitalik.eth", RESOLVER),
                supports(RESOLVER, False),
                direct(RESOLVER, "addr(bytes32)", node,
                       word_address(VITALIK_ADDRESS)),
        ):
            script.add(to, data, result)
        self.assertEqual(
            self.client(script).eth_address("vitalik.eth"), VITALIK_ADDRESS)

    def test_ensip10_resolve_unwraps_the_address(self):
        node = namehash("vitalik.eth")
        inner = encode_static_words("addr(bytes32)", [node])
        outer = abi_encode_bytes(word_address(VITALIK_ADDRESS))
        packet = encode_bytes_args(EXTENDED_RESOLVER,
                                   [dns_encode("vitalik.eth"), inner])
        script = Script()
        script.add(*registry("vitalik.eth", RESOLVER)[:2],
                   registry("vitalik.eth", RESOLVER)[2])
        to, data, result = supports(RESOLVER, True)
        script.add(to, data, result)
        script.add(RESOLVER, packet, outer)
        self.assertEqual(
            self.client(script).eth_address("Vitalik.eth"), VITALIK_ADDRESS)
        self.assertNotIn(selector("addr(bytes32)").hex(), script.seen)

    def test_wildcard_uses_parent_extended_resolver(self):
        node = namehash("sub.vitalik.eth")
        inner = encode_static_words("addr(bytes32)", [node])
        packet = encode_bytes_args(EXTENDED_RESOLVER,
                                   [dns_encode("sub.vitalik.eth"), inner])
        script = Script()
        script.add(*registry("sub.vitalik.eth", None))
        script.add(*registry("vitalik.eth", RESOLVER))
        script.add(*supports(RESOLVER, True))
        script.add(RESOLVER, packet,
                   abi_encode_bytes(word_address(VITALIK_ADDRESS)))
        self.assertEqual(
            self.client(script).eth_address("sub.vitalik.eth"),
            VITALIK_ADDRESS)

    def test_parent_without_extended_resolver_is_empty(self):
        script = Script()
        script.add(*registry("sub.vitalik.eth", None))
        script.add(*registry("vitalik.eth", RESOLVER))
        script.add(*supports(RESOLVER, False))
        self.assertIsNone(self.client(script).eth_address("sub.vitalik.eth"))

    def test_offchain_lookup_is_empty_and_does_not_fall_back(self):
        node = namehash("off.eth")
        inner = encode_static_words("addr(bytes32)", [node])
        packet = encode_bytes_args(EXTENDED_RESOLVER,
                                   [dns_encode("off.eth"), inner])
        script = Script()
        script.add(*registry("off.eth", RESOLVER))
        script.add(*supports(RESOLVER, True))
        script.add(RESOLVER, packet, RpcRevert(OFFCHAIN_LOOKUP + b"\x00"))
        self.assertIsNone(self.client(script).eth_address("off.eth"))
        self.assertNotIn(selector("addr(bytes32)").hex(), script.seen)

    def test_missing_resolver_is_empty(self):
        script = Script()
        script.add(*registry("missing.eth", None))
        self.assertIsNone(self.client(script).eth_address("missing.eth"))

    def test_contenthash_direct_call(self):
        node = namehash("vitalik.eth")
        blob = bytes.fromhex(CONTENT_LEGACY)
        script = Script()
        script.add(*registry("vitalik.eth", RESOLVER))
        script.add(*supports(RESOLVER, False))
        script.add(*direct(RESOLVER, "contenthash(bytes32)", node,
                           abi_encode_bytes(blob)))
        self.assertEqual(
            self.client(script).content("vitalik.eth"),
            {
                "codec": "ipfs-ns",
                "value": CONTENT_QM
            },
        )

    def test_reverse_requires_a_matching_forward_record(self):
        address = VITALIK_ADDRESS
        reverse = address[2:].lower() + ".addr.reverse"
        name_node = namehash(reverse)
        forward_node = namehash("vitalik.eth")
        other = "0x1111111111111111111111111111111111111111"
        script = Script()
        script.add(*registry(reverse, RESOLVER))
        script.add(*supports(RESOLVER, False))
        script.add(*direct(RESOLVER, "name(bytes32)", name_node,
                           abi_encode_bytes(b"vitalik.eth")))
        script.add(*registry("vitalik.eth", RESOLVER))
        script.add(*direct(RESOLVER, "addr(bytes32)", forward_node,
                           word_address(other)))
        # supportsInterface is cached on this client after the reverse lookup.
        self.assertIsNone(self.client(script).primary_name(address))

        match = Script()
        match.add(*registry(reverse, RESOLVER))
        match.add(*supports(RESOLVER, False))
        match.add(*direct(RESOLVER, "name(bytes32)", name_node,
                          abi_encode_bytes(b"vitalik.eth")))
        match.add(*registry("vitalik.eth", RESOLVER))
        match.add(*direct(RESOLVER, "addr(bytes32)", forward_node,
                          word_address(address)))
        self.assertEqual(
            self.client(match).primary_name(address.lower()), "vitalik.eth")

    def test_invalid_reverse_address_does_not_call_rpc(self):
        script = Script()
        self.assertIsNone(self.client(script).primary_name("not-an-address"))
        self.assertEqual(script.seen, [])

    def test_invalid_punycode_is_an_empty_lookup(self):
        script = Script()
        self.assertIsNone(self.client(script).eth_address("xn--???.eth"))
        self.assertIsNone(self.client(script).content("xn--???.eth"))
        self.assertEqual(script.seen, [])

    def test_transport_error_propagates(self):
        script = Script()
        script.add(*registry("vitalik.eth", None)[:2], TransportError("down"))
        with self.assertRaises(TransportError):
            self.client(script).eth_address("vitalik.eth")

    def test_rpc_revert_is_empty_but_other_errors_are_transport(self):
        self.assertIsNone(
            parse_rpc_result({
                "jsonrpc": "2.0",
                "id": 1,
                "error": {
                    "code": 3,
                    "message": "execution reverted",
                    "data": "0x556f1830"
                },
            }))
        with self.assertRaises(TransportError):
            parse_rpc_result({
                "jsonrpc": "2.0",
                "id": 1,
                "error": {
                    "code": -32005,
                    "message": "rate limit exceeded"
                },
            })
        raw = word_address(VITALIK_ADDRESS)
        self.assertEqual(
            parse_rpc_result({
                "jsonrpc": "2.0",
                "id": 1,
                "result": "0x" + raw.hex()
            }),
            raw,
        )
        self.assertIsNone(
            parse_rpc_result({
                "jsonrpc": "2.0",
                "id": 1,
                "result": "0x"
            }))

    def test_dns_wire_records_round_trip(self):
        first = dns.rdata.from_text("IN", "A", "1.2.3.4")
        second = dns.rdata.from_text("IN", "A", "5.6.7.8")
        rrset = dns.rrset.from_rdata(dns.name.from_text("www.example.eth."),
                                     30, first, second)
        buf = io.BytesIO()
        rrset.to_wire(buf)
        parsed = parse_wire_rrs(buf.getvalue())
        self.assertCountEqual(
            [(item["name"], item["type"], item["data"], item["ttl"])
             for item in parsed],
            [("www.example.eth", "A", "1.2.3.4", 30),
             ("www.example.eth", "A", "5.6.7.8", 30)],
        )

        node = namehash("example.eth")
        wire_hash = ens_client.keccak256(dns_encode("example.eth"))
        calldata = encode_static_words(
            "dnsRecord(bytes32,bytes32,uint16)",
            [node, wire_hash, (1).to_bytes(2, "big")],
        )
        script = Script()
        script.add(*registry("example.eth", RESOLVER))
        script.add(*supports(RESOLVER, False))
        script.add(RESOLVER, calldata, abi_encode_bytes(buf.getvalue()))
        self.assertEqual(
            self.client(script).dns_records("example.eth", "A"), parsed)


class GatewayAnswerTests(unittest.TestCase):

    def reply(self, qtype, payload, eth_name="bitsofcode.eth"):
        query = dns.message.make_query(eth_name, qtype)
        response = dns.message.make_response(query)
        rdtype = dns.rdatatype.from_text(qtype)
        fill_reply(response, eth_name, eth_name, "eth", rdtype, payload)
        return response

    def test_uri_ipfs_wallet_ptr_and_empty_fallbacks(self):
        uri = self.reply("URI", {"codec": "ipfs-ns", "value": CONTENT_QM})
        self.assertEqual(uri.rcode(), 0)
        self.assertEqual(uri.flags & 0x8400, 0x8400)
        self.assertIn(f"https://ipfs.io/ipfs/{CONTENT_QM}",
                      uri.answer[0].to_text())
        self.assertEqual(uri.authority[0].rdtype, dns.rdatatype.SOA)

        limo = self.reply("URI", None)
        self.assertIn("https://bitsofcode.eth.limo/", limo.answer[0].to_text())
        txt = self.reply("TXT", None)
        self.assertIn("https://bitsofcode.eth.limo/", txt.answer[0].to_text())

        wallet = self.reply("WALLET", VITALIK_ADDRESS, "vitalik.eth")
        self.assertEqual(int(wallet.answer[0].rdtype), 262)
        self.assertIn(VITALIK_ADDRESS, wallet.answer[0].to_text())

        ptr = self.reply("PTR", "bitsofcode.eth", VITALIK_ADDRESS + ".eth")
        self.assertIn("bitsofcode.eth.", ptr.answer[0].to_text())

        empty = self.reply("WALLET", None)
        self.assertEqual(list(empty.answer), [])
        self.assertEqual(empty.rcode(), 0)
        self.assertTrue(empty.authority)

        for qtype in ("A", "AAAA"):
            hosts = self.reply(qtype, None)
            self.assertEqual(list(hosts.answer), [])
            self.assertEqual(hosts.rcode(), 0)
            self.assertEqual(hosts.authority[0].rdtype, dns.rdatatype.SOA)
        stored = self.reply("A", [{
            "name": "bitsofcode.eth",
            "ttl": 60,
            "class": "IN",
            "type": "A",
            "data": "9.9.9.9",
        }])
        self.assertIn("9.9.9.9", stored.answer[0].to_text())

    def test_ptr_emoji_name_is_encoded_as_punycode(self):
        ptr = self.reply("PTR", "💩.eth", "xn--ls8h.eth")
        text = ptr.answer[0].to_text()
        self.assertIn("xn--ls8h.eth.", text)
        self.assertNotIn("💩", text)
        self.assertEqual(ptr.rcode(), 0)
        empty = self.reply("PTR", "xn--???.eth", "xn--ls8h.eth")
        self.assertEqual(list(empty.answer), [])
        self.assertTrue(empty.authority)

    def test_rrset_helper_matches_the_legacy_uri_shape(self):
        rows = answer_rrsets(
            "bitsofcode.eth",
            "bitsofcode.eth",
            dns.rdatatype.URI,
            {
                "codec": "ipns-ns",
                "value": "k51"
            },
        )
        text = rows[0].to_text()
        self.assertIn("1 1", text)
        self.assertIn("https://ipfs.io/ipns/k51", text)


class BitsofcodeFixtureTests(unittest.TestCase):

    def test_recorded_calls_reproduce_the_live_answers(self):
        if not FIXTURE.exists():
            self.skipTest("bitsofcode fixture has not been recorded")
        payload = json.loads(FIXTURE.read_text())
        script = Script()
        for call in payload["calls"]:
            result = call.get("result")
            value = None if result in (None,
                                       "0x") else bytes.fromhex(result[2:])
            script.add(call["to"], bytes.fromhex(call["data"][2:]), value)
        self.assertEqual(payload["address"],
                         "0x3ca2FC4f1F207178Fee25a9Aa8676ec00292dcfc")
        self.assertEqual(payload["primary"], "bitsofcode.eth")
        self.assertEqual(
            payload["content"], {
                "codec": "ipfs-ns",
                "value": "QmfFjVBz5wd66kyd89RWkJJiWEMq1Fde3XGN9MBfx47Btp",
            })
        client = EnsClient(caller=script)
        self.assertEqual(client.content(payload["name"]), payload["content"])
        self.assertEqual(client.eth_address(payload["name"]),
                         payload["address"])
        self.assertEqual(client.primary_name(payload["address"]),
                         payload["primary"])
        uri = answer_rrsets(payload["name"], payload["name"],
                            dns.rdatatype.URI, payload["content"])
        self.assertIn(payload["uri"], uri[0].to_text())


if __name__ == "__main__":
    unittest.main()
