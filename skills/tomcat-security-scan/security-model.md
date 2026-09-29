# Apache Tomcat Security Model (embedded copy)

Distilled from the canonical page so batch workers do NOT need to webfetch it per-batch.
Read this file instead of `https://tomcat.apache.org/security-model.html`.

## Provenance / freshness

- Source: https://tomcat.apache.org/security-model.html
- Fetched: 2026-09-12
- Raw HTML sha256:    `850c9ab0fdaa005e08c4492d2e6505b8fcf166090a153a3213c1c8c123a40eb4`
- Content-region sha256 (tags stripped, whitespace-normalized — robust to markup-only changes):
  `32cf297a46ef7b7f821e7d85e4a93638c1ccaba0cc6a80f1ceec10c487267246`

**Freshness check (main agent, once per campaign/resume — NOT per worker):** the page is stable
and rarely changes. Before dispatching a fresh area, re-fetch and compare; if it changed, refresh
this file + the date/hashes above:

```bash
curl -s https://tomcat.apache.org/security-model.html | sha256sum   # compare to raw HTML sha256 above
# If different, webfetch the page (markdown), re-distill into this file, update Fetched + both hashes.
```

If the raw hash differs but only in markup/whitespace, the content-region hash is the tie-breaker:
recompute it with the same tag-strip/normalize recipe and compare to the value above.

---

## The model (what the Tomcat Security Team uses to triage reports)

### Administrative users — TRUSTED
Administrative users are always trusted. Reports where an attacker already has access to or control
over any of the following are **rejected**:
- Tomcat binaries and/or scripts.
- Tomcat configuration files.
- Tomcat log files.
- The temp directory (default `$CATALINA_BASE/temp`).
- Web application working directories (default `$CATALINA_BASE/work`).
- The persisted session store.
- The Manager or Host Manager web applications shipped with Tomcat.
- The JMX API (local or remote).
- The Java Attach API or any other debugging interface.

**Exception:** reports where an attacker *tricks an administrative user* into an unintended action
(e.g. CSRF) ARE accepted.

### Web applications — TRUSTED
Web apps deployed to Tomcat are trusted; vulnerabilities in them are **application** vulnerabilities,
not Tomcat's. Apps that enable self-modification (WebDAV, HTTP PUT, similar) are expected to secure
that themselves — failure is an app vulnerability. Reports on the web apps *shipped with standard ASF
distributions* ARE accepted (check each provided app's "Security Considerations" doc section).

### Connectors — UNTRUSTED (the real attack surface)
Data received via a Connector, regardless of protocol, is **untrusted**, EXCEPT:
- The standard request attributes and any arbitrary request attributes permitted by
  `allowedRequestAttributesPattern` for an AJP connector.
- HTTP headers processed by a `RemoteIpValve`, `SSLValve`, equivalent filters (`RemoteIpFilter`) or similar.

All clients (including reverse proxies) are responsible for the consequences of the data they present.
If a client presents a (potentially malformed) request that Tomcat processes per the configured protocol's
specification, any security impact to that client is the client's responsibility.

### Clustering
Cluster traffic requires a trusted network unless `EncryptInterceptor` is used (then confidentiality +
integrity are protected, but not availability). Multicast cluster membership always requires a trusted network.

### Logging
Security-sensitive info is not logged by default apart from anything in the request URI; it may be logged
with modified/debug logging. Default logs likely contain PII (e.g. user IP). Tomcat is not responsible for
app-generated log content.

## Known non-findings (frequently reported, invalid per the model)
1. Any report depending on deserialisation within clustering code (`org.apache.catalina.ha`,
   `org.apache.catalina.tribes` + sub-packages) when `EncryptInterceptor` is NOT configured.
2. Any report depending on an attacker controlling a node within a cluster.
3. Any report depending on modification of persisted session data where the mechanism to modify it is not
   accessible to a non-administrative user.
4. Any report depending on write access to an application's `docBase`.
5. Any report depending on attacker-controlled SSI directives.

(Repeated reports of these from any source are treated as spam and get the source blocked at the ASF border.)
