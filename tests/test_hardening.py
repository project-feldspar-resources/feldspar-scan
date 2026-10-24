"""Input-handling regressions for the scanner and its output wrappers."""
import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class InputHandlingTests(unittest.TestCase):
    def test_clone_disables_symlink_checkout_and_lfs_smudge(self):
        scan = load("hardening_scan_clone", "scan.py")
        with tempfile.TemporaryDirectory() as root, \
             mock.patch.object(scan.tempfile, "mkdtemp", return_value=root), \
             mock.patch.object(scan.subprocess, "run", return_value=subprocess.CompletedProcess(
                 [], 3, stderr="")) as git, \
             mock.patch.dict(os.environ, {"FDS_CLONE_TIMEOUT": "90"}):
            self.assertEqual(scan.main(["scan.py", "https://example.com/repo"]), 3)
        args, kwargs = git.call_args
        self.assertEqual(args[0][:4], ["git", "-c", "core.symlinks=false", "clone"])
        self.assertEqual(kwargs["env"]["GIT_LFS_SKIP_SMUDGE"], "1")
        self.assertEqual(kwargs["timeout"], 90)

    def test_symlink_and_fifo_are_skipped(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO unavailable")
        with tempfile.TemporaryDirectory() as outer:
            root = os.path.join(outer, "root")
            os.mkdir(root)
            outside = os.path.join(outer, "outside.env")
            with open(outside, "w", encoding="utf-8") as fh:
                fh.write("AKIAIOSFODNN7EXAMPLE\n")
            with open(os.path.join(root, "README.md"), "w", encoding="utf-8") as fh:
                fh.write("hello\n")
            os.symlink(outside, os.path.join(root, "link.env"))
            os.mkfifo(os.path.join(root, "pipe.env"))
            result = subprocess.run(
                [sys.executable, os.path.join(ROOT, "scan.py"), root, "--no-osv"],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            doc = json.loads(result.stdout)
            self.assertEqual(doc["summary"]["files_scanned"], 1)
            self.assertEqual(doc["summary"]["skipped_non_regular"], 2)
            self.assertFalse(doc["findings"])
            scan = load("hardening_scan_read", "scan.py")
            self.assertIsNone(scan.read_text(os.path.join(root, "link.env")))
            self.assertIsNone(scan.read_text(os.path.join(root, "pipe.env")))

    def test_symlinked_directory_is_counted_and_not_descended(self):
        scan = load("hardening_scan_dir_link", "scan.py")
        with tempfile.TemporaryDirectory() as outer:
            root = os.path.join(outer, "root")
            outside = os.path.join(outer, "outside")
            os.mkdir(root)
            os.mkdir(outside)
            with open(os.path.join(outside, "secret.py"), "w") as fh:
                fh.write('api_key = "abc123def456ghi789jkl"\n')
            os.symlink(outside, os.path.join(root, "linked-dir"))
            skipped = {"non_regular": 0}
            self.assertEqual(list(scan.walk(root, skipped)), [])
            self.assertEqual(skipped["non_regular"], 1)

    def test_read_text_rejects_file_grown_past_limit_after_stat(self):
        scan = load("hardening_scan_growth", "scan.py")
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "requirements.txt")
            with open(path, "wb") as fh:
                fh.write(b"demo==1.0\n")
            limit = 8
            stale_stat = mock.Mock(st_mode=os.stat(path).st_mode, st_size=limit)
            with mock.patch.object(scan.os, "fstat", return_value=stale_stat):
                self.assertIsNone(scan.read_text(path, limit=limit))
            with open(path, "wb") as fh:
                fh.write(b"x" * limit)
            self.assertEqual(scan.read_text(path, limit=limit), "x" * limit)

    def test_html_escapes_package_and_triage_label(self):
        server = load("hardening_server", "web/server.py")
        doc = {"findings": [{"id": "F-001", "category": "dependency-vuln",
                             "severity": "high", "package": "<b>x</b>",
                             "ecosystem": "npm", "version": "1.0"}],
               "triage": {"F-001": {"action": "<i>review</i>"}}}
        rendered = server.results_html(doc)
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", rendered)
        self.assertIn("&lt;i&gt;review&lt;/i&gt;", rendered)
        self.assertNotIn("<b>x</b>", rendered)
        self.assertNotIn("<i>review</i>", rendered)

    def test_finding_caps_and_truncation_note(self):
        scan = load("hardening_scan", "scan.py")
        with tempfile.TemporaryDirectory() as root:
            line = 'api_key = "abc123def456ghi789jkl"\n'
            for n in range(51):
                with open(os.path.join(root, "file%02d.py" % n), "w", encoding="utf-8") as fh:
                    fh.write(line * 101)
            result = subprocess.run(
                [sys.executable, os.path.join(ROOT, "scan.py"), root, "--no-osv"],
                capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            doc = json.loads(result.stdout)
            self.assertEqual(len(doc["findings"]), scan.MAX_FINDINGS)
            self.assertEqual(sum(f["file"] == "file00.py" for f in doc["findings"]),
                             scan.MAX_FINDINGS_PER_FILE)
            self.assertTrue(doc["summary"]["truncated"]["findings"])
            self.assertIn("Scan limits reached", " ".join(doc["summary"]["notes"]))

    def test_file_cap_and_web_output_trim(self):
        scan = load("hardening_scan_file_cap", "scan.py")
        server = load("hardening_server_trim", "web/server.py")
        with tempfile.TemporaryDirectory() as outer:
            root = os.path.join(outer, "root")
            os.mkdir(root)
            for name in ("a.py", "b.py"):
                with open(os.path.join(root, name), "w", encoding="utf-8") as fh:
                    fh.write("hello\n")
            self.assertEqual([os.path.basename(path) for path in scan.walk(root, max_files=1)],
                             ["a.py"])
            report = os.path.join(outer, "report.json")
            with mock.patch.object(scan, "MAX_FILES", 1), mock.patch.object(
                    scan, "git_head", return_value=None):
                self.assertEqual(scan.main(["scan.py", root, "--no-osv", "--json", report]), 0)
            with open(report, encoding="utf-8") as fh:
                doc = json.load(fh)
            self.assertEqual(doc["summary"]["files_scanned"], 1)
            self.assertTrue(doc["summary"]["truncated"]["files"])

        findings = [{"id": "F-%03d" % n, "package": "package-%d" % n}
                    for n in range(server.MAX_ROWS + 1)]
        doc = {"findings": findings, "triage": {f["id"]: {"action": "review"} for f in findings}}
        rendered = server.results_html(doc)
        self.assertIn("package-199", rendered)
        self.assertNotIn("package-200", rendered)
        self.assertNotIn('"F-200"', rendered)
        self.assertIn("POST /scan", rendered)

        with mock.patch.object(server, "run_scan", return_value=(doc, None)), mock.patch.object(
                server, "rate_check", return_value=True):
            response = server.mcp_scan("https://github.com/owner/repo", "127.0.0.1")
        trimmed = response["structuredContent"]
        self.assertEqual(len(trimmed["findings"]), server.MCP_MAX_FINDINGS)
        self.assertEqual(len(trimmed["triage"]), server.MCP_MAX_FINDINGS)
        self.assertNotIn("F-200", trimmed["triage"])

    def test_mcp_scan_takes_repository_url_from_request_text(self):
        server = load("hardening_server_url_text", "web/server.py")
        self.assertEqual(server.repo_url_from(" https://github.com/owner/repo "), "https://github.com/owner/repo")
        self.assertEqual(server.repo_url_from("Scan https://github.com/owner/repo."), "https://github.com/owner/repo")
        self.assertEqual(server.repo_url_from("check (https://gitlab.com/g/p.git) and https://github.com/a/b"),
                         "https://gitlab.com/g/p.git")
        self.assertIsNone(server.repo_url_from("Scan https://github.com/owner/repo/tree/main"))
        self.assertIsNone(server.repo_url_from("Scan http://github.com/owner/repo"))
        self.assertIsNone(server.repo_url_from("Scan https://example.com/owner/repo"))
        self.assertIsNone(server.repo_url_from("Scan my repository"))

        doc = {"findings": [], "summary": {}}
        with mock.patch.object(server, "run_scan", return_value=(doc, None)) as run, mock.patch.object(
                server, "rate_check", return_value=True):
            response = server.mcp_scan("Scan https://github.com/owner/repo please", "127.0.0.1")
        run.assert_called_once_with("https://github.com/owner/repo")
        self.assertFalse(response["isError"])

        with mock.patch.object(server, "run_scan") as run:
            response = server.mcp_scan("Scan my repository", "127.0.0.1")
        run.assert_not_called()
        self.assertTrue(response["isError"])
        self.assertIn("ask the user for the repository URL", response["content"][0]["text"])

    def test_mcp_access_target_flags_refused_scans(self):
        import io
        server = load("hardening_server_limited", "web/server.py")

        class Fake:
            def __init__(self, url):
                body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                   "params": {"name": "scan_repository", "arguments": {"url": url}}}).encode()
                self.headers = {"Content-Length": str(len(body))}
                self.rfile = io.BytesIO(body)
                self.sent = []

            def client_ip(self):
                return "192.0.2.1"

            def send(self, status, body, ctype=""):
                self.sent.append(status)

        with mock.patch.object(server, "rate_check", return_value=False):
            st, target = server.Handler.handle_mcp(Fake("Scan https://github.com/owner/repo"))
        self.assertEqual(st, 200)
        self.assertEqual(target, "mcp:tools/call:scan_repository url=https://github.com/owner/repo "
                                 "arglen=34 hasurl=1 limited=rate")
        doc = {"findings": [], "summary": {}}
        with mock.patch.object(server, "rate_check", return_value=True), mock.patch.object(
                server, "run_scan", return_value=(doc, None)):
            st, target = server.Handler.handle_mcp(Fake("https://github.com/owner/repo"))
        self.assertEqual(target, "mcp:tools/call:scan_repository url=https://github.com/owner/repo")

    @unittest.skipUnless(os.path.isdir("/proc"), "requires Linux process state")
    def test_web_timeout_kills_child_process(self):
        server = load("hardening_server_timeout", "web/server.py")
        with tempfile.TemporaryDirectory() as root:
            stub = os.path.join(root, "stub.py")
            pid_file = os.path.join(root, "child.pid")
            with open(stub, "w", encoding="utf-8") as fh:
                fh.write("import os, subprocess, time\n"
                         "child = subprocess.Popen(['sleep', '300'])\n"
                         "open(os.environ['FDS_TEST_PID_FILE'], 'w').write(str(child.pid))\n"
                         "time.sleep(300)\n")
            child_pid = None
            try:
                with mock.patch.object(server, "SCAN_PY", stub), mock.patch.object(
                        server, "SCAN_TIMEOUT", 1), mock.patch.dict(
                        os.environ, {"FDS_TEST_PID_FILE": pid_file}):
                    doc, error = server.run_scan("unused")
                self.assertIsNone(doc)
                self.assertIn("exceeded", error)
                with open(pid_file, encoding="utf-8") as fh:
                    child_pid = int(fh.read())
                stat_path = "/proc/%d/stat" % child_pid
                if os.path.exists(stat_path):
                    with open(stat_path, encoding="utf-8") as fh:
                        self.assertEqual(fh.read().split()[2], "Z")
            finally:
                if child_pid is not None:
                    try:
                        os.kill(child_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_step_summary_keeps_filename_and_summary_in_one_row(self):
        action = load("hardening_action", "action_run.py")
        with tempfile.TemporaryDirectory() as root:
            report = os.path.join(root, "report.json")
            step = os.path.join(root, "step.md")
            with open(report, "w", encoding="utf-8") as fh:
                json.dump({"summary": {}, "findings": [{
                    "id": "F-001", "severity": "low", "category": "secret",
                    "file": "a`b|c\nname.txt", "summary": "line`one|two\nthree"}]}, fh)
            env = {"FDS_PATH": root, "FDS_OUTPUT": report, "FDS_OSV": "false",
                   "FDS_TRIAGE": "false", "GITHUB_STEP_SUMMARY": step}
            with mock.patch.dict(os.environ, env), mock.patch.object(
                    action.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)):
                self.assertEqual(action.main(), 0)
            with open(step, encoding="utf-8") as fh:
                rendered = fh.read()
            rows = [line for line in rendered.splitlines() if line.startswith("| F-001")]
            self.assertEqual(len(rows), 1)
            self.assertIn("a&#96;b&#124;c name.txt", rows[0])
            self.assertIn("line&#96;one&#124;two three", rows[0])
            self.assertEqual(rows[0].count("`"), 0)  # every cell is an inert text span


if __name__ == "__main__":
    unittest.main()
