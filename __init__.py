"""Hermes plugin registration for Mercury Relay."""


def register(ctx) -> None:
    """Keep the agent plugin inert; the dashboard backend owns Relay runtime."""

    del ctx
