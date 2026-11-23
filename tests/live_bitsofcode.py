#! /usr/bin/python3
"""Resolve bitsofcode.eth over JSON-RPC and refresh the recorded fixture.

Usage:
    ENS_RPC_URL=https://ethereum.publicnode.com python3 tests/live_bitsofcode.py
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bin"))

import dns.rdatatype
from ens_client import EnsClient, TransportError
from eth_redirect import answer_rrsets

NAME = "bitsofcode.eth"
PUBLIC_URLS = [
    "https://ethereum.publicnode.com",
    "https://eth.drpc.org",
    "https://eth.llamarpc.com",
    "https://1rpc.io/eth",
]
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "bitsofcode_eth.json"


def record(url):
    calls = []
    client = EnsClient(url=url, timeout=20)

    def traced(to, data):
        result = EnsClient._http_eth_call(client, to, data)
        calls.append({
            "to": to,
            "data": "0x" + data.hex(),
            "result": None if result is None else "0x" + result.hex(),
        })
        return result

    client._caller = traced
    # _http_eth_call is used only when _caller is None. Invoke it from the trace
    # above, and keep the session that __init__ already created.
    content = client.content(NAME)
    address = client.eth_address(NAME)
    primary = client.primary_name(address) if address else None
    return {
        "name":
        NAME,
        "address":
        address,
        "primary":
        primary,
        "content":
        content,
        "uri":
        None if not content else
        f"https://ipfs.io/ipfs/{content['value']}" if content.get("codec")
        == "ipfs-ns" else f"https://ipfs.io/ipns/{content['value']}",
        "rpc":
        url,
        "calls":
        calls,
    }


def main():
    urls = [os.environ["ENS_RPC_URL"]
            ] if os.environ.get("ENS_RPC_URL") else PUBLIC_URLS
    last_error = None
    payload = None
    for url in urls:
        try:
            payload = record(url)
            break
        except (OSError, ValueError, TransportError) as exc:
            last_error = exc
            print(f"failed {url}: {exc}", file=sys.stderr)
    if payload is None:
        raise SystemExit(f"no rpc endpoint worked: {last_error}")

    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(json.dumps(payload, indent=2) + "\n")
    uri = answer_rrsets(NAME, NAME, dns.rdatatype.URI, payload["content"], [])
    wallet = answer_rrsets(NAME, NAME, dns.rdatatype.from_text("WALLET"),
                           payload["address"], [])
    ptr_name = f"{payload['address']}.eth" if payload["address"] else NAME
    ptr = answer_rrsets(ptr_name, NAME, dns.rdatatype.PTR, payload["primary"],
                        [])
    print(
        json.dumps(
            {
                k: payload[k]
                for k in ("name", "address", "primary", "content", "uri",
                          "rpc")
            },
            indent=2))
    print("URI  ", uri[0].to_text() if uri else "<empty>")
    print("WALLET", wallet[0].to_text() if wallet else "<empty>")
    print("PTR ", ptr[0].to_text() if ptr else "<empty>")


if __name__ == "__main__":
    main()
