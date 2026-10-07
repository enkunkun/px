import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pxlab


def test_parse_overrides_returns_dict():
    assert pxlab.parse_overrides(["nonce_max_duration=2 minutes", "nonce_max_count=5"]) == {
        "nonce_max_duration": "2 minutes",
        "nonce_max_count": "5",
    }


def test_parse_overrides_rejects_item_without_equals():
    with pytest.raises(ValueError):
        pxlab.parse_overrides(["nonce_max_duration"])


def test_render_squid_conf_uses_defaults():
    conf = pxlab.render_squid_conf({})
    assert "auth_param digest nonce_max_duration 30 minutes\n" in conf
    assert "auth_param digest program /usr/lib/squid/digest_file_auth /etc/squid/digest_passwd\n" in conf


def test_render_squid_conf_applies_overrides():
    conf = pxlab.render_squid_conf({"nonce_max_duration": "2 minutes", "pconn_timeout": "10 seconds"})
    assert "auth_param digest nonce_max_duration 2 minutes\n" in conf
    assert "pconn_timeout 10 seconds\n" in conf


def test_render_squid_conf_rejects_unknown_key():
    with pytest.raises(KeyError):
        pxlab.render_squid_conf({"no_such_option": "1"})


@pytest.mark.parametrize("status", [401, 407, 0, 502])
def test_should_stop_on_failure(status):
    assert pxlab.should_stop({"status": status}, keep_going=False)


def test_should_not_stop_on_success():
    assert not pxlab.should_stop({"status": 200}, keep_going=False)


def test_keep_going_never_stops():
    assert not pxlab.should_stop({"status": 401}, keep_going=True)


def test_render_digest_passwd_ok():
    assert pxlab.render_digest_passwd(broken=False) == "pxuser:pxpass\n"


def test_render_digest_passwd_broken_rejects_px_password():
    assert "pxuser:pxpass\n" not in pxlab.render_digest_passwd(broken=True)
