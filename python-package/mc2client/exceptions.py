class AttestationError(Exception):
    pass


class CryptoError(Exception):
    pass


class MC2ClientComputeError(Exception):
    """Error thrown by MC2 Client due to compute service error."""


class MC2ClientConfigError(Exception):
    """Error thrown by MC2 Client due to error in configuration files."""
