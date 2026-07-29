"""Unit tests for CAPA analysis isolation helpers (no sample binaries required)."""

import struct
from unittest.mock import MagicMock, patch

import pytest

# Import helpers without constructing the full ServiceBase service when possible.
from CAPA.CAPA import (
    _error_result,
    _exit_code_is_memory_kill,
    _is_expected_analysis_error,
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

        with patch.object(svc._mp_ctx, "Process", FakeProc):
            with patch.object(svc._mp_ctx, "Queue", return_value=FakeQueue()):
                result = svc.get_capa_results(MagicMock(), "/tmp/fake")

        assert result is payload
