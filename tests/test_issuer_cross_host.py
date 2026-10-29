"""The SSH cross-host transport is permanently non-operational."""
import pytest

from zog.root_control import issuer_cross_host as legacy
from zog.root_control import issuer_https_receiver as https


def test_ssh_transport_has_no_operational_helpers():
    for name in ("transfer_and_install", "_ssh_token", "broker_main",
                 "bridge_main", "_station_binding", "_serve_broker_connection",
                 "serve_once", "_client_binding"):
        assert not hasattr(legacy, name)


def test_retired_entrypoint_fails_closed():
    with pytest.raises(legacy.CrossHostDenied, match="retired"):
        legacy.main(["client-transfer"])


def test_https_receiver_is_the_selected_transport_module():
    assert https.PURPOSE == "issuer-cloudflare-dns01"
    assert https.PROFILE_SCHEMA == "zog-issuer-https-credential-client-v1"
