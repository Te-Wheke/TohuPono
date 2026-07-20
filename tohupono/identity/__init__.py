"""Proof of Identity descriptor and manifest validation."""

from tohupono.identity.model import IdentityAssertion, IdentityDescriptor, IdentityValidationResult
from tohupono.identity.validation import (
    IDENTITY_ASSERTION_SCHEMA_VERSION,
    IDENTITY_COLLECTION_SCHEMA_VERSION,
    IDENTITY_DESCRIPTOR_SCHEMA_VERSION,
    IdentityValidationError,
    build_identity_assertion,
    build_identity_collection,
    identity_assertion_id_for_body,
    identity_assertion_ids_from_collection,
    load_identity_descriptor,
    validate_manifest_identities,
)

__all__ = [
    "IDENTITY_ASSERTION_SCHEMA_VERSION",
    "IDENTITY_COLLECTION_SCHEMA_VERSION",
    "IDENTITY_DESCRIPTOR_SCHEMA_VERSION",
    "IdentityAssertion",
    "IdentityDescriptor",
    "IdentityValidationError",
    "IdentityValidationResult",
    "build_identity_assertion",
    "build_identity_collection",
    "identity_assertion_id_for_body",
    "identity_assertion_ids_from_collection",
    "load_identity_descriptor",
    "validate_manifest_identities",
]
