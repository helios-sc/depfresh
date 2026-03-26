import click


@click.command()
def main() -> None:
    click.echo("runtime-only fixture")


if __name__ == "__main__":
    main()
