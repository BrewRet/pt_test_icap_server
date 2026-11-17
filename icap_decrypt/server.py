import socket

from cryptography.exceptions import InvalidTag

from .decrypt import decrypt_if_needed
from .http_response import update_content_length
from .icap import build_error_response, build_success_response, read_request


def handle_connection(connection) -> None:
    try:
        with connection.makefile("rb") as stream:
            http_head, body = read_request(stream)

        plaintext = decrypt_if_needed(body)
        if plaintext is not None:
            http_head = update_content_length(http_head, len(plaintext))
            body = plaintext

        reply = build_success_response(http_head, body)
    except (EOFError, ValueError, OverflowError, InvalidTag):
        reply = build_error_response()

    connection.sendall(reply)


def run_server(host: str = "0.0.0.0", port: int = 1344) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen()
        address, actual_port = listener.getsockname()
        print(f"ICAP listening on {address}:{actual_port}", flush=True)

        while True:
            connection, _ = listener.accept()
            with connection:
                try:
                    handle_connection(connection)
                except OSError:
                    continue
