# ethereum-dns-gateway
Container that provide a DNS/53 TCP/UDP gateway to ethereum names via Alchemy.com's API.
Also uses the `imperviousinc/id` library.

If the ETH name has DNS records, these will be returned (extremely rare).

If the ETH name has a `content` record (IPFS or IPNS) these will be returned if you
request a DNS record type of `URI`. For exmaple

		dig @127.0.0.8 bitsofcode.eth uri

You can access the ETH rest/api directly on port 8081, it only supports two calls right now,
`/dns/:domain/:type` and `/content/:domain`

So 

		curl http://127.0.0.8:8081/content/bitsofcode.eth

will return the `content` record (e.g. IPFS or IPNS).
