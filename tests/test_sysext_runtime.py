"""Unit tests for the shipped hardware-feature runtime that need no VM."""

import contextlib
import importlib.machinery
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNTIME = os.path.join(
    ROOT, "editions/workstation/files/system/usr/libexec/luminusos/sysext"
)


def load():
    loader = importlib.machinery.SourceFileLoader("luminusos_sysext", RUNTIME)
    mod = importlib.util.module_from_spec(
        importlib.util.spec_from_loader(loader.name, loader)
    )
    loader.exec_module(mod)
    return mod


def staged(version):
    return {"version": version, "digest": "sha256:" + version[-1] * 64}


def superseded_staged_build_stops_pulling(tmp):
    m = load()
    m.RUN = tmp
    old, new = staged("45.1"), staged("45.2")
    status = {"current": old}
    pulls = []

    def pull_one(cfg, unit_cg, ident, fid, entry):
        pulls.append((ident["version"], fid))
        status["current"] = new
        txdir = tempfile.mkdtemp(dir=tmp)
        path = os.path.join(txdir, "f.raw")
        Path(path).touch()
        return "tx", txdir, os.path.join(tmp, "nocg"), path, False

    m.pull_one = pull_one
    m.flock = lambda *a, **k: contextlib.nullcontext()
    m.reap_incoming = lambda: None
    m.pending_features = lambda ident, repair: (["a", "b"], None)
    m.fetch_descriptor = lambda cfg, ident, work: {
        "features": {f: {"expanded_budget_mib": 1} for f in ("a", "b")}
    }
    m.admission_ok = lambda cfg, budget: None
    m.count_builds = lambda: 0
    m.try_bootc_status = lambda: {"status": {"staged": status["current"]}}
    m.target_identity = lambda st, which: st["status"]["staged"]
    m.read_selection = lambda: ["a", "b"]
    m.commit = Mock()
    m.fsync_path = lambda p: None
    m.log = lambda msg: None
    m.note_failure = lambda msg: None
    cfg = {"max_builds": 4}
    rc = m.reconcile(cfg, "cg", old, ["a", "b"], "staged")
    return rc, pulls, m.commit


class SysextRuntimeTests(unittest.TestCase):
    def test_superseded_staged_build_stops_pulling(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, pulls, commit = superseded_staged_build_stops_pulling(tmp)
        self.assertEqual(rc, 0)
        self.assertEqual(pulls, [("45.1", "a")])
        commit.assert_not_called()
