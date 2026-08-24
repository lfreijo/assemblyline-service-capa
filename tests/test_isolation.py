"""Unit tests for CAPA analysis isolation helpers (no sample binaries required)."""

import struct
import sys
import types
from unittest.mock import MagicMock, patch

import pytest

# Isolation tests only need CAPA.py helpers. Stub the AL/capa packages when they
# are not installed so these unit tests can run outside the service image.
try:
    import assemblyline_v4_service.common.base  # noqa: F401
    import capa.engine  # noqa: F401
except ImportError:
    def _stub(name, **attrs):
        mod = sys.modules.get(name) or types.ModuleType(name)
        for key, value in attrs.items():
            setattr(mod, key, value)
        sys.modules[name] = mod
        parent, _, child = name.rpartition(".")
        if parent:
            setattr(sys.modules[parent], child, mod)
        return mod

    _stub("assemblyline_v4_service")
    _stub("assemblyline_v4_service.common")
    _stub("assemblyline_v4_service.common.base", ServiceBase=type("ServiceBase", (), {}))
    _stub("assemblyline_v4_service.common.request", ServiceRequest=type("ServiceRequest", (), {}))
    _stub(
        "assemblyline_v4_service.common.result",
        Result=type("Result", (), {}),
        ResultOrderedKeyValueSection=type("ResultOrderedKeyValueSection", (), {}),
        ResultSection=type("ResultSection", (), {}),
        ResultTableSection=type("ResultTableSection", (), {}),
        TableRow=type("TableRow", (), {}),
    )
    capa_mod = _stub("capa")
    _stub("capa.engine", Result=type("Result", (), {}))
    _stub("capa.main", ShouldExitError=type("ShouldExitError", (Exception,), {}))
    _stub("capa.version", __version__="test")
    rd = _stub("capa.render")
    _stub("capa.render.result_document", ResultDocument=type("ResultDocument", (), {}))
    _stub("capa.render.default", find_subrule_matches=lambda *a, **k: set())
    _stub("capa.render.utils", capability_rules=lambda *a, **k: [])
    capa_mod.engine = sys.modules["capa.engine"]
    capa_mod.main = sys.modules["capa.main"]
    capa_mod.version = sys.modules["capa.version"]

from CAPA.CAPA import (
    _error_result,
    _exit_code_is_memory_kill,
    _is_expected_analysis_error,
    _is_mp_start_failure,
    default_analysis_memory_mb,
)


class TestExpectedErrors:
    def test_struct_error_is_expected(self):
        assert _is_expected_analysis_error(struct.error("unpack requires a buffer of 4 bytes"))

    def test_assertion_error_is_expected(self):
        assert _is_expected_analysis_error(AssertionError("pe.net.mdtables is not None"))

    def test_memory_error_is_expected(self):
        assert _is_expected_analysis_error(MemoryError())

    def test_corrupt_pe_by_name(self):
        class CorruptPeFile(Exception):
            pass

        assert _is_expected_analysis_error(CorruptPeFile("truncated section headers"))

    def test_nonetype_message_is_expected(self):
        assert _is_expected_analysis_error(AttributeError("'NoneType' object has no attribute 'OptionalHeader'"))

    def test_generic_runtime_is_unexpected(self):
        assert not _is_expected_analysis_error(RuntimeError("something truly unexpected broke"))


class TestExitCodes:
    @pytest.mark.parametrize("code", [-9, -11, -6, 137, 139, 134])
    def test_memory_kill_codes(self, code):
        assert _exit_code_is_memory_kill(code)

    @pytest.mark.parametrize("code", [0, 1, -15, None])
    def test_non_memory_codes(self, code):
        assert not _exit_code_is_memory_kill(code)


class TestErrorResult:
    def test_shape(self):
        r = _error_result("/tmp/x", "boom", expected=True, status_code=17)
        assert r["status"] == "error"
        assert r["expected"] is True
        assert r["status_code"] == 17
        assert r["error"] == "boom"


class TestDefaultMemoryLimit:
    def test_falls_back_without_cgroup(self):
        with patch("CAPA.CAPA._cgroup_memory_limit_mb", return_value=None):
            assert default_analysis_memory_mb() == 3072

    def test_uses_cgroup_with_headroom(self):
        # 16 GiB container -> leave max(2048, 4096)=4096 headroom -> 12288
        with patch("CAPA.CAPA._cgroup_memory_limit_mb", return_value=16384):
            assert default_analysis_memory_mb() == 12288

    def test_small_cgroup(self):
        # 4 GiB -> headroom max(2048, 1024)=2048 -> 2048 analysis
        with patch("CAPA.CAPA._cgroup_memory_limit_mb", return_value=4096):
            assert default_analysis_memory_mb() == 2048


class TestGetCapaResultsIsolation:
    """Exercise the parent-side process lifecycle with a fake child."""

    def _service(self):
        # Avoid ServiceBase __init__ datastore wiring when possible.
        from CAPA.CAPA import CAPA

        svc = CAPA.__new__(CAPA)
        svc.log = MagicMock()
        svc.config = {"analysis_memory_mb": 1024, "analysis_timeout": 5}
        svc.argv = ["--quiet"]
        import multiprocessing as mp

        svc._mp_ctx = mp.get_context("spawn")
        return svc

    def test_timeout_kills_child(self):
        svc = self._service()
        svc.config["analysis_timeout"] = 1

        class FakeProc:
            def __init__(self, *a, **k):
                self.exitcode = None
                self._alive = True

            def start(self):
                return None

            def join(self, timeout=None):
                # Still running after the join timeout.
                return None

            def is_alive(self):
                return self._alive

            def kill(self):
                self._alive = False
                self.exitcode = -9

            def close(self):
                return None

        with patch.object(svc._mp_ctx, "Process", FakeProc):
            with patch.object(svc._mp_ctx, "Queue", return_value=MagicMock()):
                result = svc.get_capa_results(MagicMock(), "/tmp/fake")

        assert result["status"] == "error"
        assert result["expected"] is True
        assert "timed out" in result["error"]

    def test_memory_kill_exit_code(self):
        svc = self._service()

        class FakeProc:
            def __init__(self, *a, **k):
                self.exitcode = -9

            def start(self):
                return None

            def join(self, timeout=None):
                return None

            def is_alive(self):
                return False

            def kill(self):
                return None

            def close(self):
                return None

        with patch.object(svc._mp_ctx, "Process", FakeProc):
            with patch.object(svc._mp_ctx, "Queue", return_value=MagicMock()):
                result = svc.get_capa_results(MagicMock(), "/tmp/fake")

        assert result["status"] == "error"
        assert result["expected"] is True
        assert "memory limit" in result["error"]

    def test_successful_queue_result(self):
        svc = self._service()
        payload = {"path": "/tmp/fake", "status": "ok", "ok": {}, "simple_matches": [], "file_limitations": []}

        class FakeQueue:
            def get_nowait(self):
                return payload

            def close(self):
                return None

            def cancel_join_thread(self):
                return None

        class FakeProc:
            def __init__(self, *a, **k):
                self.exitcode = 0

            def start(self):
                return None

            def join(self, timeout=None):
                return None

            def is_alive(self):
                return False

            def kill(self):
                return None

            def close(self):
                return None

        with patch.object(svc._mp_ctx, "Process", FakeProc):
            with patch.object(svc._mp_ctx, "Queue", return_value=FakeQueue()):
                result = svc.get_capa_results(MagicMock(), "/tmp/fake")

        assert result is payload

    def test_start_filenotfound_retries_then_succeeds(self):
        svc = self._service()
        payload = {"path": "/tmp/fake", "status": "ok", "ok": {}, "simple_matches": [], "file_limitations": []}
        starts = {"n": 0}

        class FakeQueue:
            def get_nowait(self):
                return payload

            def close(self):
                return None

            def cancel_join_thread(self):
                return None

        class FlakyProc:
            def __init__(self, *a, **k):
                self.exitcode = 0

            def start(self):
                starts["n"] += 1
                if starts["n"] == 1:
                    raise FileNotFoundError("[Errno 2] No such file or directory")

            def join(self, timeout=None):
                return None

            def is_alive(self):
                return False

            def kill(self):
                return None

            def close(self):
                return None

        with patch("CAPA.CAPA._make_mp_context", return_value=svc._mp_ctx):
            with patch.object(svc._mp_ctx, "Process", FlakyProc):
                with patch.object(svc._mp_ctx, "Queue", return_value=FakeQueue()):
                    result = svc.get_capa_results(MagicMock(), "/tmp/fake")

        assert result is payload
        assert starts["n"] == 2
        svc.log.warning.assert_called()

    def test_start_filenotfound_twice_returns_error_not_raise(self):
        svc = self._service()

        class DeadProc:
            def __init__(self, *a, **k):
                self.exitcode = None

            def start(self):
                raise FileNotFoundError("[Errno 2] No such file or directory")

            def close(self):
                return None

        with patch("CAPA.CAPA._make_mp_context", return_value=svc._mp_ctx):
            with patch.object(svc._mp_ctx, "Process", DeadProc):
                with patch.object(svc._mp_ctx, "Queue", return_value=MagicMock()):
                    result = svc.get_capa_results(MagicMock(), "/tmp/fake")

        assert result["status"] == "error"
        assert result["expected"] is False
        assert "failed to start analysis process" in result["error"]


class TestMpContext:
    def test_uses_spawn(self):
        from CAPA.CAPA import _make_mp_context

        assert _make_mp_context().get_start_method() == "spawn"


class TestMpStartFailure:
    def test_filenotfound(self):
        assert _is_mp_start_failure(FileNotFoundError("no such file"))

    def test_conn_refused(self):
        assert _is_mp_start_failure(ConnectionRefusedError())

    def test_generic_runtime_is_not(self):
        assert not _is_mp_start_failure(RuntimeError("boom"))
