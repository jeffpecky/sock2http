Simple tool to plumb http proxy requests through a socks5 proxy.

* Clients that only speak the HTTP proxy protocol (browsers, curl, anything that honors HTTP_PROXY/HTTPS_PROXY) can use it to reach a SOCKS5 server, such as Tor or an ssh -D tunnel.

Building:
Requires Go 1.26.8 or newer.

    go build

Usage:

    socks2http -laddr <http-proxy-address> -raddr <socks-proxy-address>

For an authenticated SOCKS5 upstream, pass `-u` and `-p`:

    .\socks2http.exe -laddr 127.0.0.1:8000 -raddr <socks-proxy-address> -u "<username>" -p "<password>"

Alternatively, set `SOCKS5_USERNAME` and `SOCKS5_PASSWORD` in the environment
to avoid putting credentials directly in the command line. Command-line
credentials may be visible in process listings or saved in shell history.

Point HTTP-proxy clients at `http://127.0.0.1:8000`. For example:

    curl.exe -x http://127.0.0.1:8000 https://example.com -I

On Windows, if either the proxy or dashboard port is held by another instance
of the same sock2http executable, sock2http stops that instance (including its
proxy process tree) and reclaims the port. It will not stop unrelated
applications; choose another port with `-laddr` or `-dashboard-port` if one
owns the port.

## Cloudflare WARP mode (Windows amd64)

Run with `-warp` to use a Cloudflare WARP WireGuard tunnel instead of an
external SOCKS5 upstream:

    .\socks2http.exe -warp -laddr 127.0.0.1:8001

On first run, sock2http downloads pinned `wgcf` and `wireproxy` Windows
releases from their GitHub projects and verifies their SHA-256 checksums. It
stores the tools, WARP account, generated WireGuard profile, and wireproxy
configuration under `%APPDATA%\sock2http\warp`. If no WARP account exists, it
registers a device and accepts the WARP Terms of Service automatically. This is
the default behavior when you run `-warp`. To require an interactive
confirmation instead, use:

    .\socks2http.exe -warp -prompt-warp-terms -laddr 127.0.0.1:8001

Registration only happens when no WARP account exists yet; existing account
and profile setups do not register again. sock2http then starts and manages
wireproxy for the lifetime of the HTTP proxy process and checks that Cloudflare
reports WARP as enabled.

The components have separate responsibilities:

* `wgcf` registers a WARP device and generates its WireGuard profile.
* `wireproxy` runs that profile as a userspace WireGuard client and exposes a
  local SOCKS5 endpoint.
* `sock2http` already provides the HTTP proxy listener, so it sends requests
  through wireproxy directly. Unlike `docker-warproxy`, no additional
  SOCKS5-to-HTTP proxy such as `pproxy` is needed.

This mode uses the unofficial `wgcf` client and is not affiliated with or
endorsed by Cloudflare. WARP account registration and use remain subject to
Cloudflare's terms.

# License

MIT
