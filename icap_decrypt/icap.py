from urllib.parse import urlsplit

from .http_response import read_http_head


_CRLF = b"\r\n"
_HEX_DIGITS = b"0123456789abcdefABCDEF"
_ISTAG = b'"decrypt-v1"'


def read_request(stream) -> tuple[bytes, bytes]:
    res_body = read_icap_head(stream)
    head, content_length = read_http_head(stream, res_body)
    body = read_chunks(stream)
    if len(body) != content_length:
        raise ValueError("HTTP body length differs from Content-Length")
    return head, body


def read_icap_head(stream) -> int:
    method, target, version = _read_line(stream).split()
    if method != b"RESPMOD" or version != b"ICAP/1.0":
        raise ValueError("Expected RESPMOD and ICAP/1.0")
    uri = urlsplit(target)
    if uri.scheme != b"icap" or not uri.netloc or uri.path != b"/decrypt":
        raise ValueError("Expected an ICAP URI for the /decrypt service")

    encapsulated = None
    while True:
        line = _read_line(stream)
        if line == b"":
            break

        name, separator, value = line.partition(b":")
        if not separator or not name:
            raise ValueError("Invalid ICAP header")
        if name.lower() == b"encapsulated":
            if encapsulated is not None:
                raise ValueError("Repeated Encapsulated header")
            encapsulated = value

    if encapsulated is None:
        raise ValueError("Missing Encapsulated header")

    header, separator, body = encapsulated.partition(b",")
    if not separator or _parse_offset(header, b"res-hdr") != 0:
        raise ValueError("Expected res-hdr=0 before res-body")
    res_body = _parse_offset(body, b"res-body")
    if res_body == 0:
        raise ValueError("res-body must follow the HTTP header block")
    return res_body


def read_chunks(stream) -> bytes:
    body = bytearray()
    while True:
        size_line = _read_line(stream)
        if not size_line or any(byte not in _HEX_DIGITS for byte in size_line):
            raise ValueError("Invalid hexadecimal chunk size")

        size = int(size_line, 16)
        if size == 0:
            if _read_line(stream):
                raise ValueError("Expected an empty line after the final chunk")
            return bytes(body)

        chunk = stream.read(size)
        if len(chunk) != size:
            raise EOFError("Connection closed during chunk data")
        if stream.read(len(_CRLF)) != _CRLF:
            raise ValueError("Expected CRLF after chunk data")
        body.extend(chunk)


def build_success_response(http_head: bytes, body: bytes) -> bytes:
    encapsulated = f"res-hdr=0, res-body={len(http_head)}".encode("ascii")
    parts = [_build_head(b"200 OK", encapsulated), http_head]
    if body:
        size_line = f"{len(body):x}\r\n".encode("ascii")
        parts.extend((size_line, body, _CRLF))
    parts.append(b"0\r\n\r\n")
    return b"".join(parts)


def build_error_response() -> bytes:
    return _build_head(b"400 Bad Request", b"null-body=0")


def _build_head(status: bytes, encapsulated: bytes) -> bytes:
    lines = [
        b"ICAP/1.0 " + status,
        b"ISTag: " + _ISTAG,
        b"Connection: close",
        b"Encapsulated: " + encapsulated,
    ]
    return _CRLF.join(lines) + b"\r\n\r\n"


def _read_line(stream) -> bytes:
    line = stream.readline()
    if not line:
        raise EOFError("Connection closed while reading an ICAP line")
    if not line.endswith(_CRLF):
        raise ValueError("Expected a line ending in CRLF")
    return line[:-len(_CRLF)]


def _parse_offset(field: bytes, expected_name: bytes) -> int:
    name, separator, value = field.partition(b"=")
    value = value.strip(b" \t")
    if not separator or name.strip(b" \t") != expected_name or not value.isdigit():
        raise ValueError("Invalid offset in Encapsulated")
    return int(value)
