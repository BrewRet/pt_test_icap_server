from .server import run_server


def main() -> None:
    try:
        run_server()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
