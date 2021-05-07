from functools import partial

import pytest

from charms.layer import kubernetes_common


class TestCreateKubeConfig:
    @pytest.fixture(autouse=True)
    def _files(self, tmp_path):
        self.cfg_file = tmp_path / "config"
        self.ca_file = tmp_path / "ca.crt"
        self.ca_file.write_text("foo")
        self.ckc = partial(
            kubernetes_common.create_kubeconfig,
            self.cfg_file,
            "server",
            self.ca_file,
        )

    def test_guard_clauses(self):
        with pytest.raises(ValueError):
            self.ckc()
        assert not self.cfg_file.exists()
        with pytest.raises(ValueError):
            self.ckc(token="token", password="password")
        assert not self.cfg_file.exists()
        with pytest.raises(ValueError):
            self.ckc(key="key")
        assert not self.cfg_file.exists()

    def test_file_creation(self):
        self.ckc(password="password")
        assert self.cfg_file.exists()
        cfg_data_1 = self.cfg_file.read_text()
        assert cfg_data_1

    def test_idempotency(self):
        self.ckc(password="password")
        cfg_data_1 = self.cfg_file.read_text()
        self.ckc(password="password")
        cfg_data_2 = self.cfg_file.read_text()
        assert cfg_data_2 == cfg_data_1

    def test_efficient_updates(self):
        self.ckc(password="old_password")
        cfg_stat_1 = self.cfg_file.stat()
        self.ckc(password="old_password")
        cfg_stat_2 = self.cfg_file.stat()
        self.ckc(password="new_password")
        cfg_stat_3 = self.cfg_file.stat()
        assert cfg_stat_1.st_mtime == cfg_stat_2.st_mtime < cfg_stat_3.st_mtime

    def test_aws_iam(self):
        self.ckc(password="password", aws_iam_cluster_id="aws-cluster")
        assert self.cfg_file.exists()
        cfg_data_1 = self.cfg_file.read_text()
        assert "aws-cluster" in cfg_data_1

    def test_keystone(self):
        self.ckc(password="password", keystone=True)
        assert self.cfg_file.exists()
        cfg_data_1 = self.cfg_file.read_text()
        assert "keystone-user" in cfg_data_1
        assert "exec" in cfg_data_1

    def test_atomic_updates(self):
        self.ckc(password="old_password")
        with self.cfg_file.open("rt") as f:
            self.ckc(password="new_password")
            cfg_data_1 = f.read()
        cfg_data_2 = self.cfg_file.read_text()
        assert cfg_data_1 != cfg_data_2
        assert "old_password" in cfg_data_1
        assert "new_password" in cfg_data_2
