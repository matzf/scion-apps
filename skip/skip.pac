const scionHosts = new Set([
  "perrig.scionlab.org",
  "scionlab.org",
  "www.scionlab.org",
  "docs.scionlab.org",
  "www.scion-architecture.net",
  "netsec.ethz.ch",
  "element.inf.ethz.ch",
])

function FindProxyForURL(url, host)
{
  let mungedScionAddr = /^\d+-[-_.\dA-Fa-f]+$/
  if (host.match(mungedScionAddr) != null || 
      scionHosts.has(host)) {
	  return "PROXY {{.ProxyAddress}}";
  }
  return "DIRECT";
}
