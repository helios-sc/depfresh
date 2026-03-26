import click


@click.command()
def main() -> None:
    click.echo("direct-reference fixture")


if __name__ == "__main__":
    main()
