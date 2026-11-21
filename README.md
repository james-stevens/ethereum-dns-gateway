# ethereum-dns-gateway

DNS server (UDP port 53) that answers ENS names from Ethereum mainnet. Python calls Alchemy's JSON-RPC `eth_call` directly: ENS registry, then the resolver's `addr`, `name`, `contenthash` or `dnsRecord`. The API key is the `ALCHEMY_API_CODE` environment variable, sent to `https://eth-mainnet.g.alchemy.com/v2/<key>`.

## Queries

| RR type | Answer |
|---------|--------
| WALLET | ETH address from the resolver `addr(bytes32)` record, EIP-55 checksummed |
| PTR | Primary name of `<address>.eth`. The name is kept only when a forward `addr` lookup returns the same address |
| URI or TXT | IPFS or IPNS contenthash as `https://ipfs.io/ipfs/<cid>` or `https://ipfs.io/ipns/<cid>`. Anything else, including a missing contenthash, is `https://<name>.limo/` |
| A | ENSIP-6 `dnsRecord` when one is stored. Otherwise the IPv4 addresses in `UWR_IP_ADDRESSES` |
| other | ENSIP-6 `dnsRecord` for that type, or an empty answer |

ENSIP-10 on-chain wildcards are followed. The gateway walks parent names in the registry. If the resolver it finds is an ancestor of the queried name, it is used only when that resolver implements `resolve(bytes,bytes)`. Resolvers that implement the interface are called through `resolve` for the full DNS-encoded name, which is how on-chain wildcard data is read.

## Examples

	dig @127.0.0.1 bitsofcode.eth uri
	dig @127.0.0.1 bitsofcode.eth wallet
	dig @127.0.0.1 0x3ca2FC4f1F207178Fee25a9Aa8676ec00292dcfc.eth ptr

`bitsofcode.eth` has an on-chain IPFS contenthash, an ETH address, and a reverse record that matches that address.

## Empty answers and errors

A missing resolver, a zero address, an empty record, or a contract revert is NOERROR with a SOA in the authority section and no answer (NODATA). `A` then uses `UWR_IP_ADDRESSES`. `URI` and `TXT` use `https://<name>.limo/`. The server does not send NXDOMAIN.

If Alchemy cannot be reached, or the JSON-RPC error is not an execution revert, the DNS query is dropped so the client can retry.

## Not implemented

### CCIP-Read / EIP-3668

Off-chain lookups are not performed. When a resolver reverts with `OffchainLookup`, the gateway treats that name as having no data, same as an empty answer (including the `A` and `URI`/`TXT` fallbacks above). Names that resolve only through an off-chain gateway do not return an address, a primary name, or a contenthash.

### Other gaps

- DNS queries carry punycode (`xn--`) labels. Each of those labels is decoded with Python's `punycode` codec (not IDNA, which rejects emoji), then NFC-normalized and lowercased, and the UTF-8 result is hashed. PTR targets and other names in answers are encoded back to punycode the same way. A label that is not valid punycode is an empty answer. Full ENSIP-15 character tables are not applied. ASCII test vectors (`vitalik.eth`, `foo.eth`, `eth`) are unchanged.
- Text records and the owner address were exposed by the old REST helper and were not used for DNS. They are not queried.
- The ETH address is the legacy `addr(bytes32)` value. Multicoin `addr(bytes32,uint256)` is not read.
- IPFS and IPNS contenthashes are decoded the way the old `content-hash` package decoded them: base58btc of the CID multihash. For the common dag-pb + sha2-256 record that is a CIDv0 `Qm...` string. An IPNS identity hash (DNSLink plaintext) stays that base58 multihash rather than the raw hostname.
- ENSIP-6 `dnsRecord` is read for the queried name on the resolver discovered above. A full DNS zone walk, where the record name and the ENS name differ, is not attempted.

## Configuration

- `ALCHEMY_API_CODE` — Alchemy app key for Ethereum mainnet.
- `UWR_IP_ADDRESSES` — comma-separated IPv4 addresses returned for an `A` query that has no ENS DNS record.

The image is Alpine 3.24 with `python3`, `py3-dnspython`, `py3-requests` and `py3-pycryptodome`. It runs with a read-only root filesystem. `/tmp` and `/run` are symlinks to `/dev/shm`. Logs go to the `/opt/data` volume when syslog is not pointed at stdout.

## Tests

```
python3 -m unittest discover -s tests
```

The suite includes the EIP-137 namehash vectors, an emoji `.eth` punycode round trip, ABI encode/decode, the content-hash IPFS vector `QmRAQB6YaCyidP37UdDnjFY5vQuiBrcqdyoW1CuDgwxkD4`, and a recorded `bitsofcode.eth` JSON-RPC fixture. To refresh that fixture from a public endpoint:

```
python3 tests/live_bitsofcode.py
```
