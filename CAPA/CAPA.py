import argparse
import errno
import logging
import multiprocessing as mp
import os
import string
import struct
import traceback
from collections import defaultdict
from queue import Empty

import capa.engine
import capa.main
import capa.render.result_document as rd
import capa.version
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Result,
    ResultOrderedKeyValueSection,
    ResultSection,
    ResultTableSection,
    TableRow,
)
from capa.render.default import find_subrule_matches
from capa.render.utils import capability_rules

LOG = logging.getLogger("assemblyline.service.capa")

# Defaults used when service config does not override them.
DEFAULT_MAX_FILE_SIZE = 512000
DEFAULT_ANALYSIS_TIMEOUT = 240  # seconds; leave headroom under the 300s service timeout
# When cgroup limit cannot be read (e.g. local dev), cap the analysis child at 3 GiB.
DEFAULT_ANALYSIS_MEMORY_MB = 3072
# Leave at least this much (or 25% of the cgroup limit) for the parent service process.
ANALYSIS_MEMORY_HEADROOM_MB = 2048


def _patch_vivisect_pe_parsesections():
    # vivisect's PE.parseSections calls len(sbytes) without first checking
    # whether readAtOffset returned None for a truncated/malformed PE, so
    # samples that should produce a clean CorruptPeFile instead surface as
    # "TypeError: object of type 'NoneType' has no len()" deep in capa's
    # extractor setup. Replace it with a version that treats None as a
    # short read and raises CorruptPeFile, matching the function's own
    # intent at the same line.
    try:
        import PE
        import vstruct
        import vivisect.exc as v_exc
    except ImportError:
        return

    def parseSections(self):
        self.sections = []
        off = self.IMAGE_DOS_HEADER.e_lfanew + len(self.IMAGE_NT_HEADERS)
        off -= len(self.IMAGE_NT_HEADERS.OptionalHeader.DataDirectory)
        off += self.IMAGE_NT_HEADERS.OptionalHeader.NumberOfRvaAndSizes * len(
            vstruct.getStructure("pe.IMAGE_DATA_DIRECTORY")
        )

        secsize = len(vstruct.getStructure("pe.IMAGE_SECTION_HEADER"))
        hdrsize = secsize * self.IMAGE_NT_HEADERS.FileHeader.NumberOfSections
        sbytes = self.readAtOffset(off, hdrsize)

        if sbytes is None or len(sbytes) != hdrsize:
            raise v_exc.CorruptPeFile("truncated section headers")

        indx = off
        while sbytes:
            s = vstruct.getStructure("pe.IMAGE_SECTION_HEADER")
            s.vsParse(sbytes[:secsize])
            s.vsSetMeta("Offset", indx)
            indx += secsize
            self.sections.append(s)
            sbytes = sbytes[secsize:]

    PE.PE.parseSections = parseSections
    LOG.info("applied vivisect PE.parseSections None-safety patch")


_patch_vivisect_pe_parsesections()


def safely_get_param(request: ServiceRequest, param, default):
    param_value = default
    try:
        param_value = request.get_param(param)
    except Exception:
        pass
    return param_value


def _cgroup_memory_limit_mb():
    """Return the container memory limit in MiB, or None if unlimited/unknown."""
    candidates = (
        "/sys/fs/cgroup/memory.max",  # cgroup v2
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",  # cgroup v1
    )
    for path in candidates:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = fh.read().strip()
            if not raw or raw == "max":
                return None
            value = int(raw)
            # Some hosts report a sentinel "unlimited" near 2^63.
            if value <= 0 or value >= (1 << 62):
                return None
            return max(1, value // (1024 * 1024))
        except (OSError, ValueError):
            continue
    return None


def default_analysis_memory_mb():
    """
    Soft address-space cap for the per-file analysis subprocess.

    Sized from the cgroup limit when available so a pathological sample
    dies inside the child (soft error) instead of OOMKilling the pod and
    preempting the task. Leaves headroom for the parent service process.
    """
    limit = _cgroup_memory_limit_mb()
    if not limit:
        return DEFAULT_ANALYSIS_MEMORY_MB
    headroom = max(ANALYSIS_MEMORY_HEADROOM_MB, limit // 4)
    return max(1024, limit - headroom)


def _apply_memory_limit_mb(memory_limit_mb):
    """Best-effort RLIMIT_AS on the current process. No-op if unsupported."""
    if not memory_limit_mb or memory_limit_mb <= 0:
        return
    try:
        import resource

        limit_bytes = int(memory_limit_mb) * 1024 * 1024
        # RLIMIT_AS is not always effective on macOS; still attempt it.
        resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))
    except Exception as exc:
        LOG.debug("could not apply RLIMIT_AS(%s MiB): %s", memory_limit_mb, exc)


def _is_expected_analysis_error(exc: BaseException) -> bool:
    """
    Malware samples are often corrupt or unsupported; these failures are
    normal outcomes, not service bugs.
    """
    if isinstance(exc, (struct.error, AssertionError, MemoryError)):
        return True
    if isinstance(exc, capa.main.ShouldExitError):
        return True

    name = type(exc).__name__
    if name in {"CorruptPeFile", "InvalidFormatError", "UnsupportedFormatError"}:
        return True

    msg = str(exc).lower()
    expected_fragments = (
        "corrupt",
        "truncated",
        "unpack requires",
        "nonetype",
        "not support",
        "unsupported",
        "invalid pe",
        "invalid clr",
        "invalid format",
        "no matching",
        "does not appear",
    )
    return any(fragment in msg for fragment in expected_fragments)


def _error_result(input_file, error, *, expected=False, status_code=None, tb=None):
    result = {
        "path": input_file,
        "status": "error",
        "error": error,
        "expected": expected,
    }
    if status_code is not None:
        result["status_code"] = status_code
    if tb is not None:
        result["traceback"] = tb
    return result


def _run_capa_analysis(input_file, argv):
    """
    Pure capa analysis (no ServiceRequest). Safe to run in a child process.

    Returns a pickle-friendly dict consumed by the parent to build Result sections.
    """
    parser = argparse.ArgumentParser(description="detect capabilities in programs.")
    capa.main.install_common_args(
        parser, wanted={"rules", "signatures", "format", "os", "backend", "input_file"}
    )
    full_argv = list(argv) + [input_file]
    args = parser.parse_args(args=full_argv)

    try:
        capa.main.handle_common_args(args)
        capa.main.ensure_input_exists_from_cli(args)
        input_format = capa.main.get_input_format_from_cli(args)
        rules = capa.main.get_rules_from_cli(args)
        backend = capa.main.get_backend_from_cli(args, input_format)
        sample_path = capa.main.get_sample_path_from_cli(args, backend)
        if sample_path is None:
            os_ = "unknown"
        else:
            os_ = capa.loader.get_os(sample_path)
        extractor = capa.main.get_extractor_from_cli(args, input_format, backend)
        capabilities = capa.capabilities.common.find_capabilities(
            rules, extractor, disable_progress=True
        )
    except capa.main.ShouldExitError as e:
        return _error_result(
            input_file, str(e), expected=True, status_code=e.status_code
        )
    except Exception as e:
        tb = traceback.format_exc()
        expected = _is_expected_analysis_error(e)
        return _error_result(
            input_file,
            str(e) if expected else f"unexpected error: {e}",
            expected=expected,
            tb=tb,
        )

    meta = capa.loader.collect_metadata(
        full_argv, args.input_file, "auto", os_, [], extractor, capabilities
    )
    meta.analysis.layout = capa.loader.compute_layout(rules, extractor, capabilities.matches)

    file_limitations = []
    file_limitation_rules = [
        r
        for r in rules.rules.values()
        if r.meta.get("namespace", "").startswith("internal/limitation")
    ]
    for file_limitation_rule in file_limitation_rules:
        if file_limitation_rule.name not in capabilities.matches:
            continue
        file_limitations.append(
            {
                "name": file_limitation_rule.name,
                "description": file_limitation_rule.meta.get("description", "") or "",
            }
        )
        break

    doc = rd.ResultDocument.from_capa(meta, rules, capabilities.matches)

    return {
        "path": input_file,
        "status": "ok",
        "ok": doc.model_dump(),
        # rule names for the simple renderer (avoids pickling capa internals)
        "simple_matches": list(capabilities.matches.keys()),
        "file_limitations": file_limitations,
    }


def _analysis_process_main(input_file, argv, result_queue, memory_limit_mb):
    """Child-process entrypoint: optional RLIMIT_AS, then capa analysis."""
    # Re-apply in the child (spawn starts a fresh interpreter; fork already has
    # the patch, re-applying is harmless).
    _patch_vivisect_pe_parsesections()
    _apply_memory_limit_mb(memory_limit_mb)
    try:
        result_queue.put(_run_capa_analysis(input_file, argv))
    except Exception as e:
        result_queue.put(
            _error_result(
                input_file,
                f"unexpected error: {e}",
                expected=_is_expected_analysis_error(e),
                tb=traceback.format_exc(),
            )
        )


def _exit_code_is_memory_kill(exitcode):
    # Negative: signal number on POSIX (-9 SIGKILL, -11 SIGSEGV, -6 SIGABRT).
    # 137: 128 + SIGKILL when shells report it as an unsigned status.
    if exitcode is None:
        return False
    if exitcode in (-9, -11, -6, 137, 139, 134):
        return True
    return False


# Process.start() failures that mean the multiprocessing infrastructure died
# (typically a forkserver whose Unix socket vanished after a SIGKILL'd child).
_MP_START_ERRNOS = {
    errno.ENOENT,
    errno.ECONNREFUSED,
    errno.ECONNRESET,
    errno.ECONNABORTED,
    errno.EPIPE,
}


def _is_mp_start_failure(exc: BaseException) -> bool:
    if isinstance(exc, (FileNotFoundError, ConnectionRefusedError, ConnectionResetError, BrokenPipeError)):
        return True
    return isinstance(exc, OSError) and getattr(exc, "errno", None) in _MP_START_ERRNOS


def _close_mp_resources(proc, result_queue):
    if result_queue is not None:
        try:
            result_queue.close()
        except Exception:
            pass
        try:
            result_queue.cancel_join_thread()
        except Exception:
            pass
    if proc is not None:
        try:
            proc.close()
        except Exception:
            pass


def _make_mp_context():
    """
    Always spawn.

    forkserver is cheaper if you preload capa/vivisect once, but it keeps a
    long-lived server that imports __main__ (the AL service + capa). We
    SIGKILL analysis children on timeout and RLIMIT_AS, and those kills (or
    a cgroup OOM) take the forkserver down. After that every Process.start()
    fails with FileNotFoundError until the pod restarts — the prod failure
    mode on cluster h.
    """
    return mp.get_context("spawn")


class CAPA(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)
        self.argv = []
        self._mp_ctx = _make_mp_context()

    def start(self):
        # capa does not declare a __str__ or a __repr__ for that special object, so without the following, we get
        #   "<capa.engine.Result object at 0x7f17da579880>"
        # in the ResultSection if we want to use the full capabilities report
        capa.engine.Result.__repr__ = lambda self: (
            f"{self.__class__.__module__}.{self.__class__.__qualname__}("
            f"success={self.success}, "
            f"statement: {self.statement}, "
            f"children: {self.children}, "
            f"locations: {self.locations}"
            ")"
        )
        self.argv = [
            "--quiet",
            "--signatures",
            # Ruleset downloaded from https://github.com/mandiant/capa/tree/v9.3.1/sigs
            os.path.join(os.path.dirname(__file__), "sigs"),
            "--rules",
            # Ruleset downloaded from https://github.com/mandiant/capa-rules/archive/refs/tags/v9.4.0.zip
            os.path.join(os.path.dirname(__file__), "capa-rules-9.4.0"),
            "--format",
            "auto",
            "--backend",
            "auto",
            "--os",
            "auto",
        ]
        analysis_mb = self.config.get("analysis_memory_mb")
        if analysis_mb is None:
            analysis_mb = default_analysis_memory_mb()
        self.log.info(
            "CAPA ready (capa %s, analysis_memory_mb=%s, analysis_timeout=%s)",
            capa.version.__version__,
            analysis_mb,
            self.config.get("analysis_timeout", DEFAULT_ANALYSIS_TIMEOUT),
        )

    def _analysis_memory_mb(self):
        configured = self.config.get("analysis_memory_mb")
        if configured is None:
            return default_analysis_memory_mb()
        return int(configured)

    def _analysis_timeout(self):
        return int(self.config.get("analysis_timeout", DEFAULT_ANALYSIS_TIMEOUT))

    def _reset_mp_context(self):
        """Drop a dead spawn/forkserver context so the next start() is clean."""
        self._mp_ctx = _make_mp_context()

    def get_capa_results(self, request: ServiceRequest, input_file):
        """
        Run capa in an isolated subprocess so vivisect/capa memory is released
        after every file and a pathological sample cannot OOMKill the pod.
        """
        memory_limit_mb = self._analysis_memory_mb()
        timeout = self._analysis_timeout()
        last_start_error = None

        # One retry after resetting the mp context: a dead forkserver (or a
        # similarly broken spawn helper) fails start() with FileNotFoundError
        # on every subsequent file until we replace it.
        for attempt in range(2):
            result_queue = None
            proc = None
            try:
                result_queue = self._mp_ctx.Queue()
                proc = self._mp_ctx.Process(
                    target=_analysis_process_main,
                    args=(input_file, self.argv, result_queue, memory_limit_mb),
                    name="capa-analysis",
                )
                proc.start()
            except Exception as e:
                _close_mp_resources(proc, result_queue)
                if _is_mp_start_failure(e) and attempt == 0:
                    last_start_error = e
                    self.log.warning(
                        "capa child start failed (%s); resetting multiprocessing context and retrying",
                        e,
                    )
                    self._reset_mp_context()
                    continue
                if _is_mp_start_failure(e):
                    return _error_result(
                        input_file,
                        f"failed to start analysis process: {e}",
                        expected=False,
                    )
                raise
            break
        else:
            return _error_result(
                input_file,
                f"failed to start analysis process: {last_start_error}",
                expected=False,
            )

        try:
            proc.join(timeout=timeout)

            if proc.is_alive():
                self.log.warning(
                    "capa analysis timed out after %ss for %s; killing child",
                    timeout,
                    input_file,
                )
                proc.kill()
                proc.join(5)
                return _error_result(
                    input_file,
                    f"analysis timed out after {timeout}s",
                    expected=True,
                )

            if proc.exitcode not in (0, None):
                if _exit_code_is_memory_kill(proc.exitcode):
                    return _error_result(
                        input_file,
                        f"analysis exceeded memory limit (~{memory_limit_mb} MiB)",
                        expected=True,
                    )
                # Child may still have put a structured result before dying.
                try:
                    return result_queue.get_nowait()
                except Empty:
                    return _error_result(
                        input_file,
                        f"analysis process exited with code {proc.exitcode}",
                        expected=False,
                    )

            try:
                return result_queue.get_nowait()
            except Empty:
                return _error_result(
                    input_file,
                    "analysis process produced no result",
                    expected=False,
                )
        finally:
            _close_mp_resources(proc, result_queue)

    def _apply_ok_result(self, request, result):
        for limitation in result.get("file_limitations") or []:
            res = ResultSection(f"File Limitation - {limitation['name']}")
            res.add_line(limitation.get("description", ""))
            request.result.add_section(res)

        renderer = safely_get_param(request, "renderer", "default")
        if renderer == "simple":
            self.simple_view_from_names(request, result.get("simple_matches") or [])
            return

        doc = rd.ResultDocument.model_validate(result["ok"])
        if renderer == "verbose":
            self.render_rules(request, doc)
        else:
            self.default_view(request, doc)

    def default_view(self, request, doc: rd.ResultDocument):
        tactics = defaultdict(set)
        objectives = defaultdict(set)
        caps = []
        subrule_matches = find_subrule_matches(doc)
        for rule in capability_rules(doc):
            for attack in rule.meta.attack:
                tactics[attack.tactic].add((attack.technique, attack.subtechnique, attack.id))
            for mbc in rule.meta.mbc:
                objectives[mbc.objective].add((mbc.behavior, mbc.method, mbc.id))
            if rule.meta.name not in subrule_matches:
                count = len(rule.matches)
                caps.append((rule.meta.name, count, rule.meta.namespace if rule.meta.namespace else ""))

        self.render_attack(request, tactics)
        self.render_mbc(request, objectives)
        self.render_capabilities(request, caps)

    def render_attack(self, request, tactics):
        added = False
        res = ResultTableSection("ATT&CK")
        res.set_heuristic(1)
        for tactic, techniques in sorted(tactics.items()):
            for technique, subtechnique, id in sorted(techniques):
                res.add_row(
                    TableRow(
                        {
                            "ATT&CK Tactic": tactic.upper(),
                            "ATT&CK Technique": technique if not subtechnique else f"{technique} ({subtechnique})",
                            "ATT&CK ID": id,
                        }
                    )
                )
                res.heuristic.add_attack_id(id)
                added = True
        if added:
            request.result.add_section(res)

    def render_mbc(self, request, objectives):
        added = False
        res = ResultTableSection("Malware Behavior Catalog")
        res.set_heuristic(1)
        for objective, behaviors in sorted(objectives.items()):
            for behavior, method, id in sorted(behaviors):
                res.add_row(
                    TableRow(
                        {
                            "MBC Objective": objective.upper(),
                            "MBC Behavior": behavior if not method else f"{behavior} ({method})",
                            "MBC ID": id,
                        }
                    )
                )
                res.heuristic.add_signature_id(id)
                added = True
        if added:
            request.result.add_section(res)

    def render_capabilities(self, request, caps):
        added = False
        res = ResultTableSection("Capabilities")
        res.set_heuristic(1)
        for cap, count, namespace in sorted(caps):
            if count == 1:
                capability = cap
            else:
                capability = f"{cap} ({count} matches)"
            res.add_row(
                TableRow(
                    {
                        "Capability": capability,
                        "Namespace": namespace,
                    }
                )
            )
            if not cap.startswith("(internal)"):
                res.heuristic.add_signature_id(cap)
            added = True
        if added:
            request.result.add_section(res)

    def simple_view_from_names(self, request, match_names):
        def remove_hash_ending(rule_name):
            if len(rule_name) > 33 and rule_name[-33] == "/" and all(c in string.hexdigits for c in rule_name[-32:]):
                return remove_hash_ending(rule_name[:-33])
            return rule_name

        capa_graph_data = list({remove_hash_ending(x) for x in match_names})

        res = ResultSection("CAPA Information")
        res.add_lines(capa_graph_data)

        request.result.add_section(res)

    def simple_view(self, request, capabilities):
        # Kept for compatibility with anything that still passes a capa capabilities object.
        self.simple_view_from_names(request, list(capabilities.matches.keys()))

    def render_rules(self, request, doc: rd.ResultDocument):
        # See https://github.com/mandiant/capa/blob/v6.1.0/capa/render/vverbose.py#L281
        for _, _, rule in sorted((rule.meta.namespace or "", rule.meta.name, rule) for rule in doc.rules.values()):
            if rule.meta.is_subscope_rule:
                continue

            count = len(rule.matches)
            if count == 1:
                capability = rule.meta.name
            else:
                capability = f"{rule.meta.name} ({count} matches)"

            res = ResultOrderedKeyValueSection(capability)

            if not rule.meta.name.startswith("(internal)") or rule.meta.attack or rule.meta.mbc:
                res.set_heuristic(1)

            if not rule.meta.name.startswith("(internal)"):
                res.heuristic.add_signature_id(rule.meta.name)

            res.add_item("namespace", rule.meta.namespace if rule.meta.namespace else "")

            if rule.meta.maec.analysis_conclusion or rule.meta.maec.analysis_conclusion_ov:
                res.add_item(
                    "maec/analysis-conclusion",
                    rule.meta.maec.analysis_conclusion or rule.meta.maec.analysis_conclusion_ov,
                )

            if rule.meta.maec.malware_family:
                res.add_item("maec/malware-family", rule.meta.maec.malware_family)

            if rule.meta.maec.malware_category or rule.meta.maec.malware_category_ov:
                res.add_item(
                    "maec/malware-category", rule.meta.maec.malware_category or rule.meta.maec.malware_category_ov
                )

            if rule.meta.description:
                res.add_item("description", rule.meta.description)

            if rule.meta.attack:
                [res.heuristic.add_attack_id(data.id) for data in rule.meta.attack]
                res.add_item(
                    "att&ck", ", ".join(["%s [%s]" % ("::".join(data.parts), data.id) for data in rule.meta.attack])
                )

            if rule.meta.mbc:
                [res.heuristic.add_signature_id(data.id) for data in rule.meta.mbc]
                res.add_item("mbc", ", ".join(["%s [%s]" % ("::".join(data.parts), data.id) for data in rule.meta.mbc]))

            request.result.add_section(res)

    def execute(self, request):
        request.result = Result()

        if request.file_size > self.config.get("max_file_size", DEFAULT_MAX_FILE_SIZE):
            return

        request.set_service_context(f"CAPA {self.get_tool_version()}")

        result = self.get_capa_results(request, request.file_path)
        status = result.get("status")
        if status == "error":
            expected = result.get("expected", False)
            message = result.get("error") or "unknown capa error"
            if expected:
                self.log.warning("%s", message)
            else:
                tb = result.get("traceback")
                if tb:
                    self.log.error("%s\n%s", message, tb)
                else:
                    self.log.error("%s", message)
        elif status == "ok":
            self._apply_ok_result(request, result)
        else:
            raise ValueError(f"unexpected status: {status}")

    def get_tool_version(self):
        return capa.version.__version__