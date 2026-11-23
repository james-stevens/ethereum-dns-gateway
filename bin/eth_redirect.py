#! /usr/bin/python3
# (c) Copyright 2022-2025, James Stevens ... see LICENSE for details
# Alternative license arrangements possible, contact me for more information
"""DNS/53 gateway from ENS names to WALLET, PTR and URI records."""

import argparse
import os
import socket
import sys
import threading
import time
import types
from syslog import syslog

import dns.exception
import dns.flags
import dns.immutable
import dns.message
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.txtbase
import dns.rrset
from ens_client import EnsClient, TransportError, select_rpc_endpoint, to_puny

AUTH_IP = "0.0.0.0"
DNS_MAX_QUERY = 1024
DEFAULT_TTL = 3600

KNOWN_CODECS = {
    "ipns-ns": "https://ipfs.io/ipns/{value}",
    "ipfs-ns": "https://ipfs.io/ipfs/{value}",
}

LIMO_URL = "https://{eth_name}.limo/"

sock = None
queries = {}
resolvers = []
to_syslog = False
with_logging = False


def ensure_wallet_type():
    """Register IANA type 262 when this dnspython build predates WALLET."""
    try:
        dns.rdatatype.from_text("WALLET")
        return
    except dns.rdatatype.UnknownRdatatype:
        pass

    @dns.immutable.immutable
    class WALLET(dns.rdtypes.txtbase.TXTBase):
        """Public wallet address."""

    module = types.ModuleType("dns_wallet")
    module.WALLET = WALLET
    dns.rdata.register_type(module, 262, "WALLET", rdclass=dns.rdataclass.ANY)


ensure_wallet_type()
WALLET = dns.rdatatype.from_text("WALLET")


def log(line):
    if not with_logging:
        return
    if to_syslog:
        syslog(line)
    else:
        print(line)


def presentation(rdtype, eth_name, payload):
    data = payload or {}
    base = "1 1 " if rdtype == dns.rdatatype.URI else " "
    if isinstance(
            data,
            dict) and data.get("codec") in KNOWN_CODECS and data.get("value"):
        return base + KNOWN_CODECS[data["codec"]].format(value=data["value"])
    return base + LIMO_URL.format(eth_name=eth_name)


def soa_rrset(tld):
    return dns.rrset.from_text(
        tld + ".",
        DEFAULT_TTL,
        "IN",
        "SOA",
        f"{tld}. {tld}. 1 10800 3600 604800 3600",
    )


def answer_rrsets(qname, eth_name, rdtype, payload):
    qtype = dns.rdatatype.to_text(rdtype)
    if rdtype in (dns.rdatatype.URI, dns.rdatatype.TXT):
        text = presentation(rdtype, eth_name, payload)
        return [
            dns.rrset.from_text(f"{qname}.", DEFAULT_TTL, "IN", qtype, text)
        ]
    if rdtype == WALLET:
        if not payload:
            return []
        text = f'"ETH" "{payload}"'
        return [
            dns.rrset.from_text(f"{qname}.", DEFAULT_TTL, "IN", qtype, text)
        ]
    if rdtype == dns.rdatatype.PTR:
        if not payload:
            return []
        target = to_puny(str(payload))
        if not target:
            return []
        return [
            dns.rrset.from_text(f"{qname}.", DEFAULT_TTL, "IN", qtype,
                                target.rstrip(".") + ".")
        ]
    out = []
    for rec in payload or []:
        out.append(
            dns.rrset.from_text(rec["name"] + ".", rec["ttl"], rec["class"],
                                rec["type"], rec["data"]))
    return out


def fill_reply(reply, qname, eth_name, tld, rdtype, payload):
    reply.index = None
    reply.flags = 0x8400
    reply.authority.append(soa_rrset(tld))
    for rr in answer_rrsets(qname, eth_name, rdtype, payload):
        reply.answer.append(rr)
    return reply


def udp_limit(reply):
    """Bytes the client can accept. EDNS uses the query payload; otherwise 512."""
    if reply.edns >= 0 and reply.request_payload:
        return reply.request_payload
    return 512


def reply_wire(reply, qname):
    """Render a UDP reply, or a TC-only reply if the full message does not fit."""
    limit = udp_limit(reply)
    try:
        return reply.to_wire(max_size=limit)
    except dns.exception.TooBig:
        reply.flags |= dns.flags.TC
        reply.answer = []
        reply.authority = []
        reply.additional = []
        print(f"DNS reply truncated: {qname} limit {limit}", file=sys.stderr)
        return reply.to_wire(max_size=limit)


def run_resolver(idx):
    me = resolvers[idx]
    while True:
        while me.query is None:
            time.sleep(0.1)
        log(f">>>>   GIVEN: {me.idx}, {me.query.asker}")
        me.answer()
        me.clean_up()


class Resolver:

    def __init__(self, idx, rpc_url):
        self.ens = EnsClient(url=rpc_url)
        self.query = None
        self.idx = idx
        self.thread = None
        self.restart()

    def restart(self):
        self.thread = threading.Thread(target=run_resolver,
                                       args=(self.idx, ),
                                       daemon=True)

    def run(self):
        self.thread.start()

    def lookup(self, qry):
        if qry.rdtype in (dns.rdatatype.URI, dns.rdatatype.TXT):
            log(f"ASKING: content {qry.eth_name}")
            return self.ens.content(qry.eth_name)
        if qry.rdtype == WALLET:
            log(f"ASKING: wallet {qry.eth_name}")
            return self.ens.eth_address(qry.eth_name)
        if qry.rdtype == dns.rdatatype.PTR:
            label = qry.eth_name.split(".")[0]
            log(f"ASKING: ptr {label}")
            return self.ens.primary_name(label)
        log(f"ASKING: dns {qry.eth_name} {qry.qtype}")
        return self.ens.dns_records(qry.eth_name, qry.qtype)

    def answer(self):
        if self.query is None:
            return
        qry = self.query
        try:
            payload = self.lookup(qry)
        except TransportError as exc:
            log(f"RPC ERROR: {exc}")
            return

        reply = dns.message.make_response(qry.line_query)
        reply.id = qry.asker[0]
        fill_reply(reply, qry.qname, qry.eth_name, qry.tld, qry.rdtype,
                   payload)
        sock.sendto(reply_wire(reply, qry.qname), qry.asker[1])

    def clean_up(self):
        if self.query.key in queries:
            del queries[self.query.key]
        self.query = None


class Query:

    def __init__(self, qry, sender):
        self.line_query = qry
        self.qname = str(qry.question[0].name)[:-1]
        eth_name = self.qname[11:] if self.qname[:11].lower(
        ) == "_http._tcp." else self.qname
        self.eth_name = eth_name.lower()
        self.rdtype = qry.question[0].rdtype
        self.qtype = dns.rdatatype.to_text(self.rdtype)
        self.key = f"{self.rdtype}|{self.qname}"
        self.asker = (qry.id, sender)
        self.tld = self.eth_name
        if (pos := self.eth_name.find(".")) >= 0:
            self.tld = self.eth_name[pos + 1:]


def find_next():
    for resolver in resolvers:
        if not resolver.thread.is_alive():
            resolver.restart()
            resolver.query = None
            resolver.run()

        if resolver.query is None:
            return resolver.idx
    return None


def main(argv=None):
    global to_syslog, with_logging, sock, queries, resolvers

    parser = argparse.ArgumentParser(description="ENS DNS gateway")
    parser.add_argument("-t", "--threads", default=2)
    parser.add_argument("-s", "--syslog", action="store_true", default=False)
    parser.add_argument("-l", "--logging", action="store_true")
    args = parser.parse_args(argv)

    to_syslog = args.syslog
    with_logging = args.logging
    rpc_url, rpc_label = select_rpc_endpoint(os.environ)
    print(f"ENS RPC endpoint: {rpc_label}", file=sys.stderr)

    queries = {}
    resolvers = [Resolver(idx, rpc_url) for idx in range(int(args.threads))]
    for resolver in resolvers:
        resolver.run()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((AUTH_IP, 53))

    while True:
        bin_qry, sender = sock.recvfrom(DNS_MAX_QUERY)
        log(f">>>>  PACKET: {sender}")
        if bin_qry[2] & 0x80:
            continue

        new_query = Query(dns.message.from_wire(bin_qry), sender)
        if new_query.key in queries:
            resolv = resolvers[queries[new_query.key]]
            log(f">>>> ALREADY: {new_query.asker} to {resolv.idx}")
            resolv.query.asker = new_query.asker
        elif (idx := find_next()) is not None:
            log(f">>>>  GIVING: {new_query.asker} to {idx}")
            queries[new_query.key] = idx
            resolvers[idx].query = new_query

    sock.close()


if __name__ == "__main__":
    raise SystemExit(main())
