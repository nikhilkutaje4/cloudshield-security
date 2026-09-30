"""
WebAuthn (passkey / laptop fingerprint) helpers for the 3rd login factor.

Replaces the old mfa/fingerprint.py hash comparison. The fingerprint itself
never reaches the server: the laptop's reader (Windows Hello / Touch ID /
Android) unlocks a private key that stays on the device, and we only store
the matching PUBLIC key and verify signatures made with it.

This module is Flask-route-free on purpose (no circular imports with app.py).
"""
import os

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

RP_NAME = "CloudSecurity Vault"


def rp_settings(request):
    """Return (rp_id, origin) for this deployment.

    Set WEBAUTHN_RP_ID and WEBAUTHN_ORIGIN on Render for production, e.g.
        WEBAUTHN_RP_ID=myapp.onrender.com
        WEBAUTHN_ORIGIN=https://myapp.onrender.com
    Without them we derive both from the request (fine for localhost).
    """
    rp_id = os.environ.get("WEBAUTHN_RP_ID")
    origin = os.environ.get("WEBAUTHN_ORIGIN")
    if rp_id and origin:
        return rp_id, origin

    host = request.host.split(":")[0]
    local = host in ("localhost", "127.0.0.1")
    scheme = "http" if local else "https"   # Render terminates TLS at its proxy
    return host, f"{scheme}://{request.host}"


def create_registration_options(request, user_row, existing_credential_ids):
    rp_id, _ = rp_settings(request)
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=RP_NAME,
        user_id=f"user-{user_row['id']}".encode(),
        user_name=user_row["username"],
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=cid) for cid in existing_credential_ids
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,   # built-in reader
            resident_key=ResidentKeyRequirement.DISCOURAGED,
            user_verification=UserVerificationRequirement.REQUIRED,      # must use finger/PIN
        ),
    )
    return bytes_to_base64url(options.challenge), options_to_json(options)


def check_registration(request, credential_json, challenge_b64):
    """Returns (credential_id, public_key, sign_count). Raises on failure."""
    rp_id, origin = rp_settings(request)
    v = verify_registration_response(
        credential=credential_json,
        expected_challenge=base64url_to_bytes(challenge_b64),
        expected_rp_id=rp_id,
        expected_origin=origin,
        require_user_verification=True,
    )
    return v.credential_id, v.credential_public_key, v.sign_count


def create_login_options(request, credential_ids):
    rp_id, _ = rp_settings(request)
    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=[PublicKeyCredentialDescriptor(id=cid) for cid in credential_ids],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return bytes_to_base64url(options.challenge), options_to_json(options)


def check_login(request, credential_json, challenge_b64, public_key, sign_count):
    """Returns the new sign_count. Raises on failure."""
    rp_id, origin = rp_settings(request)
    v = verify_authentication_response(
        credential=credential_json,
        expected_challenge=base64url_to_bytes(challenge_b64),
        expected_rp_id=rp_id,
        expected_origin=origin,
        credential_public_key=public_key,
        credential_current_sign_count=sign_count,
        require_user_verification=True,
    )
    return v.new_sign_count


def raw_id_bytes(credential_json):
    return base64url_to_bytes(credential_json["id"])
