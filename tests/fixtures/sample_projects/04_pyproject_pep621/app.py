import click
from packaging.version import Version


@click.command()
def main() -> None:
    v = Version("1.0.0")
    click.echo(f"Hello from depfresh test! Version: {v}")


if __name__ == "__main__":
    main()
