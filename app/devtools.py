"""Small, loopback-only DevTools WebSocket client (no third-party dependency)."""
import base64
import hashlib
import json
import os
import socket
import struct
import time
from urllib.parse import urlsplit


class DevToolsError(ValueError):
    pass


class DevTools:
    LIMIT = 16 * 1024 * 1024

    def __init__(self, url):
        parts = urlsplit(url)
        if parts.scheme != "ws" or parts.hostname not in ("127.0.0.1", "localhost") or not parts.path.startswith("/devtools/"):
            raise DevToolsError("허용되지 않은 브라우저 제어 주소입니다.")
        self.socket = socket.create_connection((parts.hostname, parts.port), timeout=5)
        self.buffer = b""
        self.sequence = 0
        try:
            key = base64.b64encode(os.urandom(16)).decode("ascii")
            request = (f"GET {parts.path} HTTP/1.1\r\nHost: {parts.hostname}:{parts.port}\r\n"
                       f"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                       "Sec-WebSocket-Version: 13\r\n\r\n")
            self.socket.sendall(request.encode("ascii"))
            header = b""
            while b"\r\n\r\n" not in header:
                chunk = self.socket.recv(4096)
                if not chunk or len(header) > 32768:
                    raise DevToolsError("브라우저 제어 연결을 열지 못했습니다.")
                header += chunk
            header, self.buffer = header.split(b"\r\n\r\n", 1)
            expected = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
            fields = {line.split(b":", 1)[0].lower(): line.split(b":", 1)[1].strip() for line in header.split(b"\r\n")[1:] if b":" in line}
            if b" 101 " not in header.split(b"\r\n")[0] or fields.get(b"sec-websocket-accept") != expected:
                raise DevToolsError("브라우저 제어 연결 검증에 실패했습니다.")
        except Exception:
            self.close()
            raise

    def close(self):
        self.socket.close()

    def read(self, size):
        while len(self.buffer) < size:
            chunk = self.socket.recv(min(65536, size - len(self.buffer)))
            if not chunk:
                raise DevToolsError("검색 브라우저가 닫혔습니다.")
            self.buffer += chunk
        result, self.buffer = self.buffer[:size], self.buffer[size:]
        return result

    def send(self, payload, opcode=1):
        mask = os.urandom(4)
        length = len(payload)
        header = bytes((0x80 | opcode, 0x80 | length)) if length < 126 else bytes((0x80 | opcode, 0x80 | 126)) + struct.pack("!H", length) if length <= 65535 else bytes((0x80 | opcode, 0x80 | 127)) + struct.pack("!Q", length)
        self.socket.sendall(header + mask + bytes(value ^ mask[i % 4] for i, value in enumerate(payload)))

    def receive(self, deadline):
        fragments = bytearray()
        while time.monotonic() < deadline:
            self.socket.settimeout(max(0.1, min(5, deadline - time.monotonic())))
            first, second = self.read(2)
            opcode = first & 15
            length = second & 127
            if length == 126:
                length = struct.unpack("!H", self.read(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self.read(8))[0]
            if length + len(fragments) > self.LIMIT:
                raise DevToolsError("브라우저 응답 크기 제한을 초과했습니다.")
            mask = self.read(4) if second & 128 else None
            payload = self.read(length)
            if mask:
                payload = bytes(value ^ mask[i % 4] for i, value in enumerate(payload))
            if opcode == 8:
                raise DevToolsError("검색 브라우저가 닫혔습니다.")
            if opcode == 9:
                self.send(payload, opcode=10)
                continue
            if opcode == 10:
                continue
            if opcode not in (0, 1):
                raise DevToolsError("브라우저 응답 형식을 인식하지 못했습니다.")
            fragments.extend(payload)
            if first & 0x80:
                return json.loads(fragments)
        raise TimeoutError("브라우저 제어 응답 시간 초과")

    def call(self, method, params=None, session=None, timeout=8):
        self.sequence += 1
        message = dict(id=self.sequence, method=method, params=params or {})
        if session:
            message["sessionId"] = session
        self.send(json.dumps(message).encode())
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            response = self.receive(deadline)
            if response.get("id") == self.sequence:
                if "error" in response:
                    raise DevToolsError("검색 브라우저 명령을 처리하지 못했습니다.")
                return response.get("result", {})
        raise TimeoutError("브라우저 제어 응답 시간 초과")
