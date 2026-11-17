_CRLF = b"\r\n"
_HEADER_END = b"\r\n\r\n"


def read_http_head(stream, size: int) -> tuple[bytes, int]:
    head = stream.read(size)
    if len(head) != size:
        raise EOFError("Connection closed during the HTTP header block")

    header_block, separator, extra = head.partition(_HEADER_END)
    if not separator or extra:
        raise ValueError("res-body does not point to the end of the HTTP header block")

    lines = header_block.split(_CRLF)
    protocol, status_code, *_ = lines[0].split(maxsplit=2)
    if not protocol.startswith(b"HTTP/") or len(status_code) != 3 or not status_code.isdigit():
        raise ValueError("Invalid HTTP status line")

    _, content_length = _find_content_length(lines)
    return head, content_length


def update_content_length(head: bytes, size: int) -> bytes:
    lines = head.split(_CRLF)
    index, _ = _find_content_length(lines)
    name, _, _ = lines[index].partition(b":")
    lines[index] = name + b": " + str(size).encode("ascii")
    return _CRLF.join(lines)


def _find_content_length(lines: list[bytes]) -> tuple[int, int]:
    field = None
    for index, line in enumerate(lines[1:], start=1):
        if not line:
            break
        name, separator, value = line.partition(b":")
        if name.lower() != b"content-length":
            continue

        value = value.strip(b" \t")
        if not separator or not value.isdigit() or field is not None:
            raise ValueError("Invalid or repeated Content-Length")
        field = index, int(value)

    if field is None:
        raise ValueError("Missing Content-Length")
    return field
