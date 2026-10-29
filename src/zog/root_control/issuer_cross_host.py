"""Retired SSH-specific cross-host issuer transport.

The approved transport is the purpose-scoped HTTPS receiver in
``zog.root_control.issuer_https_receiver``. Historical SSH implementation
details remain in repository history; no installed runtime entrypoint or
callable transfer/broker/forced-command helper is retained here.
"""
from . import issuer_credentials as credentials


class CrossHostDenied(credentials.IssuerCredentialError):
    """Fixed secret-free denial for attempts to use the retired transport."""


def retired():
    raise CrossHostDenied("SSH issuer credential transport retired") from None


def main(argv=None):
    retired()


if __name__ == "__main__":
    main()
