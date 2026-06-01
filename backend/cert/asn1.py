"""
ASN.1 encoding utilities and X.509 certificate helpers for Aegis custom extensions.
"""

from __future__ import annotations

from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier

_OID_MAP = {
    "pqc_status": "1.3.6.1.4.1.55555.1.1",
    "fips_compliant": "1.3.6.1.4.1.55555.1.2",
    "broken_algorithms": "1.3.6.1.4.1.55555.1.3",
    "remediation_bundle_id": "1.3.6.1.4.1.55555.1.4",
}


def load_certificate(pem: str) -> x509.Certificate:
    """Load a PEM certificate into a cryptography X.509 object."""
    return x509.load_pem_x509_certificate(pem.encode("utf-8"))


def _encode_utf8_asn1(payload: str) -> bytes:
    raw = payload.encode("utf-8")
    if len(raw) < 128:
        length_bytes = bytes([len(raw)])
    else:
        encoded_length = []
        remaining = len(raw)
        while remaining:
            encoded_length.append(remaining & 0xFF)
            remaining >>= 8
        encoded_length.reverse()
        length_bytes = bytes([0x80 | len(encoded_length), *encoded_length])
    return bytes([0x0C]) + length_bytes + raw


def _decode_utf8_asn1(payload: bytes) -> str:
    if not payload:
        return ""
    if payload[0] != 0x0C:
        return payload.decode("utf-8")
    first_length_byte = payload[1]
    if first_length_byte < 0x80:
        content_start = 2
        content_length = first_length_byte
    else:
        length_of_length = first_length_byte & 0x7F
        content_start = 2 + length_of_length
        content_length = int.from_bytes(payload[2:content_start], byteorder="big")
    return payload[content_start : content_start + content_length].decode("utf-8")


def get_extension_payload(certificate: x509.Certificate, oid_name: str) -> str | None:
    """Return a decoded UTF-8 payload for one custom Aegis extension."""
    oid = ObjectIdentifier(_OID_MAP[oid_name])
    try:
        extension = certificate.extensions.get_extension_for_oid(oid)
    except x509.ExtensionNotFound:
        return None
    value = extension.value
    if isinstance(value, x509.UnrecognizedExtension):
        return _decode_utf8_asn1(value.value)
    return None
