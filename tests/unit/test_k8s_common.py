import json
import string
from subprocess import CalledProcessError
from pathlib import Path
import pytest
from unittest.mock import Mock, call, patch
from charms.reactive import endpoint_from_flag


from charms.layer import kubernetes_common as kc


@pytest.mark.parametrize(
    "taint, key, value, effect",
    [
        (
            "kubernetes.io/uninitialized=true:NoSchedule",
            "kubernetes.io/uninitialized",
            "true",
            "NoSchedule",
        ),
        (
            "kubernetes.io/uninitialized:NoExecute",
            "kubernetes.io/uninitialized",
            None,
            "NoExecute",
        ),
    ],
)
def test_v1_taints_from_string_success(taint, key, value, effect):
    obj = kc.v1_taint_from_string(taint)
    assert obj.get("key") == key
    assert obj.get("value") == value
    assert obj.get("effect") == effect


@pytest.mark.parametrize(
    "taint, issue",
    [
        ("kubernetes.io/uninitialized=true:BadEffect", "effect"),
        ("kubernetes.io/uninitialized=NoExecute", "colon"),
        ("kubernetes.io=uninitialized=true:NoExecute", "equals"),
    ],
)
def test_v1_taints_from_string_failure(taint, issue):
    with pytest.raises(ValueError) as ie:
        kc.v1_taint_from_string(taint)
    assert issue in str(ie.value)


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
    os_listdir.return_value = ["01-default.conflist", "10-cni.conflist"]
    cni = endpoint_from_flag("cni.available")
    cni.get_config.return_value = {
        "cidr": "192.168.0.0/24",
        "cni-conf-file": "10-cni.conflist",
    }
    kc.configure_default_cni("test-cni")
    os_remove.assert_called_once_with("/etc/cni/net.d/01-default.conflist")
    os_symlink.assert_called_once_with(
        "10-cni.conflist", "/etc/cni/net.d/01-default.conflist"
    )


def test_get_bind_addrs():
    response = Path("tests", "data", "ip_addr_json").read_bytes()
    with patch.object(kc, "check_output", return_value=response):
        addrs = kc.get_bind_addrs()
    assert addrs == ["10.246.154.77"]


@patch.object(kc, "get_version")
@patch.object(kc, "get_node_ip", Mock(return_value="10.1.1.1"))
@patch.object(kc, "workaround_lxd_kernel_params", Mock())
@patch.object(kc, "configure_kubernetes_service")
@patch.object(kc, "hookenv")
@patch("os.makedirs", Mock())
@patch.object(kc, "open")
@pytest.mark.parametrize("version", [(1, 27, 0), (1, 26, 0)], ids=["1.27.0", "1.26.0"])
@pytest.mark.parametrize("runtime", ["remote", "local"])
def test_configure_kubelet(
    f_open, hookenv, conf_service, get_version, version, runtime, tmp_path
):
    get_version.return_value = version
    endpoint_from_flag(
        "endpoint.container-runtime.available"
    ).get_runtime.return_value = runtime
    hookenv.config.return_value = "{}"
    kc.configure_kubelet(".test.domain", "10.10.10.10", "registry.k8s.io")

    f_open.assert_called_once_with("/root/cdk/kubelet/config.yaml", "w")
    with f_open() as f:
        first_call = call("# Generated by kubernetes-common library, do not edit\n")
        f.write.assert_has_calls([first_call])

    conf_service.assert_called_once()
    if runtime == "local" and version == (1, 27, 0):
        # Ensure we get a log message about invalid runtimes
        hookenv.log.assert_called_once_with(
            "Runtime local is no longer supported in 1.27.0", level="ERROR"
        )
    else:
        hookenv.log.assert_not_called()
