import json
import string
from subprocess import CalledProcessError
from pathlib import Path
from unittest.mock import Mock, patch
from charms.reactive import endpoint_from_flag

from charms.layer import kubernetes_common as kc


def test_token_generator():
    alphanum = string.ascii_letters + string.digits
    token = kc.token_generator(10)
    assert len(token) == 10
    unknown_chars = set(token) - set(alphanum)
    assert not unknown_chars


def test_get_secret_names(monkeypatch):
    monkeypatch.setattr(kc, "kubectl", Mock())
    kc.kubectl.side_effect = [
        CalledProcessError(1, "none"),
        FileNotFoundError,
        "{}".encode("utf8"),
        json.dumps(
            {
                "items": [
                    {
                        "metadata": {"name": "secret-id"},
                        "data": {"username": "dXNlcg=="},
                    },
                ],
            }
        ).encode("utf8"),
    ]
    assert kc.get_secret_names() == {}
    assert kc.get_secret_names() == {}
    assert kc.get_secret_names() == {}
    assert kc.get_secret_names() == {"user": "secret-id"}


def test_generate_rfc1123():
    alphanum = string.ascii_letters + string.digits
    token = kc.generate_rfc1123(1000)
    assert len(token) == 253
    unknown_chars = set(token) - set(alphanum)
    assert not unknown_chars


def test_create_secret(monkeypatch):
    monkeypatch.setattr(kc, "render", Mock())
    monkeypatch.setattr(kc, "kubectl_manifest", Mock())
    monkeypatch.setattr(kc, "get_secret_names", Mock())
    monkeypatch.setattr(kc, "generate_rfc1123", Mock())
    kc.kubectl_manifest.side_effect = [True, False]
    kc.get_secret_names.side_effect = [{"username": "secret-id"}, {}]
    kc.generate_rfc1123.return_value = "foo"
    assert kc.create_secret("token", "username", "user", "groups")
    assert kc.render.call_args[1]["context"] == {
        "groups": "Z3JvdXBz",
        "password": "dXNlcjo6dG9rZW4=",
        "secret_name": "secret-id",
        "secret_namespace": "kube-system",
        "type": "juju.is/token-auth",
        "user": "dXNlcg==",
        "username": "dXNlcm5hbWU=",
    }
    assert not kc.create_secret("token", "username", "user", "groups")
    assert kc.render.call_args[1]["context"] == {
        "groups": "Z3JvdXBz",
        "password": "dXNlcjo6dG9rZW4=",
        "secret_name": "auth-user-foo",
        "secret_namespace": "kube-system",
        "type": "juju.is/token-auth",
        "user": "dXNlcg==",
        "username": "dXNlcm5hbWU=",
    }


def test_get_secret_password(monkeypatch):
    monkeypatch.setattr(kc, "kubectl", Mock())
    monkeypatch.setattr(kc, "Path", Mock())
    monkeypatch.setattr(kc, "yaml", Mock())
    kc.kubectl.side_effect = [
        CalledProcessError(1, "none"),
        CalledProcessError(1, "none"),
        CalledProcessError(1, "none"),
        CalledProcessError(1, "none"),
        CalledProcessError(1, "none"),
        CalledProcessError(1, "none"),
        FileNotFoundError,
        json.dumps({}).encode("utf8"),
        json.dumps({"items": []}).encode("utf8"),
        json.dumps({"items": []}).encode("utf8"),
        json.dumps({"items": [{}]}).encode("utf8"),
        json.dumps({"items": [{"data": {}}]}).encode("utf8"),
        json.dumps(
            {"items": [{"data": {"username": "Ym9i", "password": "c2VjcmV0"}}]}
        ).encode("utf8"),
        json.dumps(
            {"items": [{"data": {"username": "dXNlcm5hbWU=", "password": "c2VjcmV0"}}]}
        ).encode("utf8"),
    ]
    kc.yaml.safe_load.side_effect = [
        {},
        {"users": None},
        {"users": []},
        {"users": [{"user": {}}]},
        {"users": [{"user": {"token": "secret"}}]},
    ]
    assert kc.get_secret_password("username") is None
    assert kc.get_secret_password("admin") is None
    assert kc.get_secret_password("admin") is None
    assert kc.get_secret_password("admin") is None
    assert kc.get_secret_password("admin") is None
    assert kc.get_secret_password("admin") == "secret"
    assert kc.get_secret_password("username") is None
    assert kc.get_secret_password("username") is None
    assert kc.get_secret_password("username") is None
    assert kc.get_secret_password("username") is None
    assert kc.get_secret_password("username") is None
    assert kc.get_secret_password("username") is None
    assert kc.get_secret_password("username") is None
    assert kc.get_secret_password("username") == "secret"


@patch("os.listdir")
@patch("os.remove")
@patch("os.symlink")
def test_configure_default_cni(os_symlink, os_remove, os_listdir):
    os_listdir.return_value = ["05-default.conflist", "10-cni.conflist"]
    cni = endpoint_from_flag("cni.available")
    cni.get_config.return_value = {
        "cidr": "192.168.0.0/24",
        "cni-conf-file": "10-cni.conflist",
    }
    kc.configure_default_cni("test-cni")
    os_remove.assert_called_once_with("/etc/cni/net.d/05-default.conflist")
    os_symlink.assert_called_once_with(
        "10-cni.conflist", "/etc/cni/net.d/05-default.conflist"
    )


def test_get_bind_addrs():
    response = Path("tests", "data", "ip_addr_json").read_bytes()
    with patch.object(kc, "check_output", return_value=response):
        addrs = kc.get_bind_addrs()
    assert addrs == ["10.246.154.77"]
