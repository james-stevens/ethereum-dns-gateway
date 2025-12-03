# ethereum-dns-gateway
Container that provide a DNS/53 TCP/UDP gateway to ethereum names via Alchemy.com's API.
Also uses the `imperviousinc/id` library.

It supports four different DNS/RR-Type queries.

| RR-Type | Response
|---------|---------
| WALLET  | Response with a WALLET RR with the wallet id of the ETH name
| PTR     | If the query is a wallet id with the sufix `.eth` it will respond with the wallet name
| URI or TXT | If the ETH name has a `content` record, it will respond with an IPFS/IPNS URL to decode it
| A | If the name has a DNS record, it will returned, otherwise it will return the IP Address of a URI redirector

## Examples

	dig @127.0.0.1 vitalik.eth. uri  # returns a link to their IPFS
	dig @127.0.0.1 vitalik.eth. wallet  # returns a WALLET record with their wallet id
	dig @127.0.0.1 0x3ca2FC4f1F207178Fee25a9Aa8676ec00292dcfc.eth ptr   # returns a PTR record of the wallet name


## Directly accessing the API

You can access the ETH rest/api directly on port 8081, it supports the following calls

```
app.get('/dns/:domain/:type', function (req, res) {
app.get('/name/:wallet', function (req, res) {
app.get('/text/:domain', function (req, res) {
app.get('/owner/:domain', function (req, res) {
app.get('/wallet/:domain', function (req, res) {
app.get('/content/:domain', function (req, res) {
```

So 

		curl http://127.0.0.8:8081/content/bitsofcode.eth

will return the `content` record (e.g. IPFS or IPNS).
