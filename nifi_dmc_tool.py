#!/usr/bin/env python3
"""
nifi_map_cache_tool.py

Command-line client for Apache NiFi's DistributedMapCacheServer / MapCacheServer
(the "Distributed Map Cache" controller service, renamed to "MapCacheServer" in
NiFi 2.x). There is no REST endpoint for this service -- it only speaks its own
small binary TCP protocol, the same one used internally by the
DistributedMapCacheClientService / MapCacheClientService and by processors like
PutDistributedMapCache and FetchDistributedMapCache. This script implements
that protocol directly so you can add, remove, and list cache entries from the
command line, without going through a NiFi flow.

Protocol summary (from org.apache.nifi.distributed.cache.protocol.ProtocolHandshake
and org.apache.nifi.distributed.cache.server.map.MapCacheServer in the NiFi source):

  1. Handshake: client sends magic bytes b"NiFi", then a 4-byte big-endian
     protocol version. Server replies with one status byte:
       20 (RESOURCE_OK)              -> version accepted
       21 (DIFFERENT_RESOURCE_VERSION) -> server sends its preferred version
                                          (4-byte int), client must re-propose
       255 (ABORT)                   -> server sends a UTF error string and
                                          closes the connection
  2. Each request: client sends a Java-style UTF string naming the action
     ("get", "put", "putIfAbsent", "containsKey", "remove", "removeAndGet",
     "keySet", "close", ...), followed by action-specific arguments. Keys and
     values are sent as a 4-byte length prefix + raw bytes.
  3. "keySet" (list all keys) and "removeAndGet" require protocol version 3.
     Version 3 is what recent NiFi releases (1.x and 2.x) speak by default, but
     if a server only supports version 1 it will downgrade the handshake and
     keySet/removeAndGet will not be available. This tool falls back cleanly
     and reports that case.

Important caveats:
  - "list" and "clear" both enumerate keys via the server-side "keySet"
    operation. This is only implemented by the default in-memory (and
    persistent) cache implementation. Backends like the Redis-based
    DistributedMapCacheClient do not support it, and the NiFi client API
    itself defaults to raising UnsupportedOperationException for keySet --
    this script talks to the server directly, so it works as long as the
    server you're pointed at is the standard NiFi MapCacheServer /
    DistributedMapCacheServer. "clear" removes keys one at a time (via the
    same "remove" operation "remove" itself uses) rather than the server's
    "removeByPattern" operation, which depends on server-side regex matching
    that isn't exception-safe on the server and can behave inconsistently.
  - This is a raw socket protocol client, not the NiFi REST API. It requires
    direct TCP (optionally TLS) connectivity to the controller service's
    configured host/port -- the same host/port you'd put in a
    MapCacheClientService controller service, not the NiFi API port (usually
    8080/8443).
  - Keys/values are treated as UTF-8 text by default. Use --hex if your cache
    entries are non-text.

Usage examples:
  python3 nifi_map_cache_tool.py --host nifi.example.com --port 4557 add mykey myvalue
  python3 nifi_map_cache_tool.py --host nifi.example.com --port 4557 add mykey myvalue --if-absent
  python3 nifi_map_cache_tool.py --host nifi.example.com --port 4557 get mykey
  python3 nifi_map_cache_tool.py --host nifi.example.com --port 4557 remove mykey
  python3 nifi_map_cache_tool.py --host nifi.example.com --port 4557 list
  python3 nifi_map_cache_tool.py --host nifi.example.com --port 4557 list --values
  python3 nifi_map_cache_tool.py --host nifi.example.com --port 4557 contains mykey

TLS (if the DistributedMapCacheServer / MapCacheServer has an SSL Context
Service configured):
  python3 nifi_map_cache_tool.py --host nifi.example.com --port 4557 --tls \
      --cert client.pem --key client-key.pem --ca ca.pem list
"""

import argparse
import socket
import ssl
import struct
import sys

MAGIC_HEADER = b"NiFi"
RESOURCE_OK = 20
DIFFERENT_RESOURCE_VERSION = 21
ABORT = 255

PREFERRED_VERSION = 3
SUPPORTED_VERSIONS = (3, 2, 1)  # ordered by preference, highest first


class ProtocolError(Exception):
    pass


class NiFiMapCacheClient:
    """Minimal client for NiFi's DistributedMapCacheServer / MapCacheServer wire protocol."""

    def __init__(self, host, port, timeout=10.0, tls_context=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.tls_context = tls_context
        self.sock = None
        self.rfile = None
        self.version = None

    # -- connection lifecycle -------------------------------------------------

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def connect(self):
        raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.tls_context is not None:
            self.sock = self.tls_context.wrap_socket(raw_sock, server_hostname=self.host)
        else:
            self.sock = raw_sock
        self.rfile = self.sock.makefile("rb")
        self._handshake()

    def close(self):
        if self.sock is not None:
            try:
                self._write_utf("close")
                self.sock.sendall(b"")  # no response expected for close
            except OSError:
                pass
            finally:
                try:
                    self.rfile.close()
                finally:
                    self.sock.close()
                self.sock = None

    # -- low-level I/O helpers -------------------------------------------------

    def _send(self, data):
        self.sock.sendall(data)

    def _read_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.rfile.read(n - len(buf))
            if not chunk:
                raise ProtocolError("Connection closed unexpectedly by server")
            buf += chunk
        return buf

    def _read_byte(self):
        return self._read_exact(1)[0]

    def _read_int(self):
        return struct.unpack(">i", self._read_exact(4))[0]

    def _read_long(self):
        return struct.unpack(">q", self._read_exact(8))[0]

    def _read_boolean(self):
        return self._read_byte() != 0

    def _read_utf(self):
        (length,) = struct.unpack(">H", self._read_exact(2))
        return self._read_exact(length).decode("utf-8")

    def _write_utf(self, s):
        data = s.encode("utf-8")
        self._send(struct.pack(">H", len(data)) + data)

    def _write_value(self, data):
        self._send(struct.pack(">i", len(data)) + data)

    def _read_value_or_none(self):
        length = self._read_int()
        if length == 0:
            return None
        return self._read_exact(length)

    # -- handshake -------------------------------------------------------------

    def _handshake(self):
        self._send(MAGIC_HEADER)
        self._negotiate_version(PREFERRED_VERSION)

    def _negotiate_version(self, proposed_version):
        self._send(struct.pack(">i", proposed_version))
        status = self._read_byte()
        if status == RESOURCE_OK:
            self.version = proposed_version
            return
        if status == DIFFERENT_RESOURCE_VERSION:
            server_preferred = self._read_int()
            fallback = next((v for v in SUPPORTED_VERSIONS if v <= server_preferred), None)
            if fallback is None:
                raise ProtocolError(
                    f"Could not agree on a protocol version (server wants <= {server_preferred})"
                )
            self._negotiate_version(fallback)
            return
        if status == ABORT:
            message = self._read_utf()
            raise ProtocolError(f"Server aborted handshake: {message}")
        raise ProtocolError(f"Unexpected handshake status code: {status}")

    def _require_version(self, min_version, feature):
        if self.version < min_version:
            raise ProtocolError(
                f"'{feature}' requires protocol version {min_version}, "
                f"but the server negotiated version {self.version}"
            )

    # -- operations --------------------------------------------------------

    def put(self, key, value):
        """Unconditionally set key to value. Returns True."""
        self._write_utf("put")
        self._write_value(key)
        self._write_value(value)
        return self._read_boolean()

    def put_if_absent(self, key, value):
        """Set key to value only if not already present. Returns True if the put happened."""
        self._write_utf("putIfAbsent")
        self._write_value(key)
        self._write_value(value)
        return self._read_boolean()

    def get(self, key):
        """Return the value for key, or None if not present."""
        self._write_utf("get")
        self._write_value(key)
        return self._read_value_or_none()

    def contains_key(self, key):
        self._write_utf("containsKey")
        self._write_value(key)
        return self._read_boolean()

    def remove(self, key):
        """Remove key. Returns True if an entry was removed."""
        self._write_utf("remove")
        self._write_value(key)
        return self._read_boolean()

    def remove_and_get(self, key):
        """Remove key, returning the removed value (or None if absent). Requires v3."""
        self._require_version(3, "removeAndGet")
        self._write_utf("removeAndGet")
        self._write_value(key)
        return self._read_value_or_none()

    def key_set(self):
        """Return the list of all keys currently in the cache. Requires v3."""
        self._require_version(3, "keySet")
        self._write_utf("keySet")
        count = self._read_int()
        keys = []
        for _ in range(count):
            length = self._read_int()
            keys.append(self._read_exact(length))
        return keys

    def remove_by_pattern(self, regex):
        """Remove every key whose UTF-8 string form fully matches regex. Returns the number removed.

        Note: on the server, this operation runs a Java regex match with no
        exception handling around it. If anything about the match goes wrong
        the connection can be dropped without a response. clear() below does
        not use this -- it removes keys one at a time instead, which is
        slower but far more robust.
        """
        self._write_utf("removeByPattern")
        self._write_utf(regex)
        return self._read_long()

    def clear(self):
        """Delete every entry in the cache. Returns the number of entries removed.

        Implemented as keySet() followed by an individual remove() per key,
        rather than the server's removeByPattern operation. removeByPattern
        depends on server-side regex matching that isn't exception-safe and
        can behave inconsistently across NiFi versions/cache backends;
        removing keys one at a time uses the same simple, well-tested
        primitives that "list" and "count" already rely on.
        """
        removed = 0
        for key in self.key_set():
            if self.remove(key):
                removed += 1
        return removed

    def count(self):
        """Return the number of entries currently in the cache. Requires v3 (uses keySet)."""
        return len(self.key_set())


# -- CLI ------------------------------------------------------------------


def build_tls_context(args):
    if not args.tls:
        return None
    context = ssl.create_default_context(cafile=args.ca)
    if args.cert:
        context.load_cert_chain(certfile=args.cert, keyfile=args.key)
    if args.insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def encode_arg(value, as_hex):
    if as_hex:
        return bytes.fromhex(value)
    return value.encode("utf-8")


def decode_bytes(data, as_hex):
    if data is None:
        return None
    if as_hex:
        return data.hex()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.hex() + " (binary, shown as hex)"


def main():
    parser = argparse.ArgumentParser(
        description="Add, remove, and list entries in a NiFi DistributedMapCacheServer / MapCacheServer.",
    )
    parser.add_argument("--host", required=True, help="Hostname of the cache server")
    parser.add_argument("--port", required=True, type=int, help="Port of the cache server")
    parser.add_argument("--timeout", type=float, default=10.0, help="Socket timeout in seconds (default: 10)")
    parser.add_argument("--hex", action="store_true", help="Treat keys/values as hex-encoded bytes instead of UTF-8 text")
    parser.add_argument("--tls", action="store_true", help="Connect using TLS (if the server's SSL Context Service is configured)")
    parser.add_argument("--cert", help="Client certificate file for TLS (PEM)")
    parser.add_argument("--key", help="Client private key file for TLS (PEM)")
    parser.add_argument("--ca", help="CA bundle to verify the server certificate (PEM)")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS certificate/hostname verification (not recommended)")

    subparsers = parser.add_subparsers(dest="command", required=True)

    p_add = subparsers.add_parser("add", help="Add or overwrite a cache entry")
    p_add.add_argument("key")
    p_add.add_argument("value")
    p_add.add_argument("--if-absent", action="store_true", help="Only set the value if the key is not already present")

    p_get = subparsers.add_parser("get", help="Get the value for a key")
    p_get.add_argument("key")

    p_remove = subparsers.add_parser("remove", help="Remove a cache entry")
    p_remove.add_argument("key")
    p_remove.add_argument("--print-value", action="store_true", help="Print the removed value (uses removeAndGet)")

    p_contains = subparsers.add_parser("contains", help="Check whether a key exists")
    p_contains.add_argument("key")

    p_list = subparsers.add_parser("list", help="List all keys currently in the cache")
    p_list.add_argument("--values", action="store_true", help="Also fetch and print the value for each key")

    subparsers.add_parser("count", help="Print the number of entries currently in the cache")

    p_clear = subparsers.add_parser("clear", help="Delete ALL entries in the cache")
    p_clear.add_argument("--yes", action="store_true", help="Skip the confirmation prompt")

    args = parser.parse_args()

    try:
        tls_context = build_tls_context(args)
    except ssl.SSLError as e:
        print(f"TLS configuration error: {e}", file=sys.stderr)
        return 1

    try:
        with NiFiMapCacheClient(args.host, args.port, timeout=args.timeout, tls_context=tls_context) as client:
            if args.command == "add":
                key = encode_arg(args.key, args.hex)
                value = encode_arg(args.value, args.hex)
                if args.if_absent:
                    added = client.put_if_absent(key, value)
                    print("added" if added else "key already present, not overwritten")
                else:
                    client.put(key, value)
                    print("ok")

            elif args.command == "get":
                key = encode_arg(args.key, args.hex)
                value = client.get(key)
                if value is None:
                    print("(not found)")
                    return 1
                print(decode_bytes(value, args.hex))

            elif args.command == "remove":
                key = encode_arg(args.key, args.hex)
                if args.print_value:
                    removed = client.remove_and_get(key)
                    if removed is None:
                        print("(not found)")
                        return 1
                    print(decode_bytes(removed, args.hex))
                else:
                    removed = client.remove(key)
                    print("removed" if removed else "(not found)")
                    if not removed:
                        return 1

            elif args.command == "contains":
                key = encode_arg(args.key, args.hex)
                print("yes" if client.contains_key(key) else "no")

            elif args.command == "list":
                keys = client.key_set()
                if not keys:
                    print("(cache is empty)")
                for key in keys:
                    if args.values:
                        value = client.get(key)
                        print(f"{decode_bytes(key, args.hex)} = {decode_bytes(value, args.hex)}")
                    else:
                        print(decode_bytes(key, args.hex))

            elif args.command == "count":
                print(client.count())

            elif args.command == "clear":
                if not args.yes:
                    if not sys.stdin.isatty():
                        print(
                            "Refusing to clear the cache without confirmation in a non-interactive "
                            "session. Re-run with --yes to proceed.",
                            file=sys.stderr,
                        )
                        return 1
                    reply = input(
                        f"This will delete ALL entries in the cache at {args.host}:{args.port}. "
                        "Type 'yes' to continue: "
                    )
                    if reply.strip().lower() != "yes":
                        print("Aborted, nothing was deleted.")
                        return 1
                removed = client.clear()
                print(f"deleted {removed} entr{'y' if removed == 1 else 'ies'}")

    except ProtocolError as e:
        print(f"Protocol error: {e}", file=sys.stderr)
        return 1
    except (OSError, socket.timeout) as e:
        print(f"Connection error: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

