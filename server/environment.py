import random
from typing import Any, Dict, Optional
from uuid import uuid4

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import State

from .grader import get_grader
from .models import CloudRedTeamAction, CloudRedTeamObservation
from .scenarios import load_scenario


ACTIVE_ENV = None

def get_active_env():
    global ACTIVE_ENV
    return ACTIVE_ENV

class CloudRedTeamEnvironment(
    Environment[CloudRedTeamAction, CloudRedTeamObservation, State]
):
    def __init__(self):
        global ACTIVE_ENV
        ACTIVE_ENV = self
        super().__init__()
        self.t = "easy"
        self.zz = load_scenario(self.t)
        self.zz["access_level"] = "none"
        self.zz["alerts_triggered"] = 0
        self.zz["budget_remaining"] = int((self.zz.get("limits", {}) or {}).get("budget") or 0)
        self.zz["rate_counters"] = {}
        self.g = get_grader(self.t)
        self.la: Optional[str] = None
        self.st = State(episode_id=str(uuid4()), step_count=0)

    def _l(self, m: str):
        self.zz.setdefault("logs", []).append(m)

    def _o(self, q: Optional[list[str]] = None) -> CloudRedTeamObservation:
        services = self.zz.get("services", [])
        k = self.zz.get("agent_knowledge", {}) or {}
        if self.t == "easy" and not k.get("discovered_storage"):
            services = []
        if self.t in ("medium", "hard") and not k.get("discovered_services"):
            services = []
        return CloudRedTeamObservation(
            services_visible=services,
            agent_knowledge=self.zz.get("agent_knowledge", {}),
            access_level=self.zz.get("access_level", "none"),
            alerts_triggered=self.zz.get("alerts_triggered", 0),
            logs=q or [],
            done=False,
            reward= 0.011,
        )

    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        task_id: str = "easy",
        **kwargs: Any,
    ) -> CloudRedTeamObservation:
        self.t = task_id
        self.zz = load_scenario(task_id, seed=seed)
        self.zz["access_level"] = "none"
        self.zz["alerts_triggered"] = 0
        self.zz["budget_remaining"] = int((self.zz.get("limits", {}) or {}).get("budget") or 0)
        self.zz["rate_counters"] = {}
        self.zz["_seed"] = int(seed or 0)
        self.g = get_grader(task_id)
        self.la = None
        self.st = State(
            episode_id=episode_id or str(uuid4()),
            step_count=0,
            task_id=task_id,
        )
        return self._o(q=["[+] Environment reset"])

    def step(
        self,
        action: CloudRedTeamAction,
        timeout_s: Optional[float] = None,
        **kwargs: Any,
    ) -> CloudRedTeamObservation:
        self.st.step_count += 1
        q: list[str] = []
        p =  0.011

        if action.action == self.la:
            p -= 0.1
        self.la = action.action
        p -= 0.01

        def a(x: str):
            q.append(x)
            self._l(x)

        k = self.zz.setdefault("agent_knowledge", {})
        u = action.action
        r = action.params or {}
        defender = self.zz.setdefault("defender", {})

        limits = self.zz.get("limits", {}) or {}
        rate_counters = self.zz.setdefault("rate_counters", {})

        action_cost = 1
        if u == "query_api":
            action_cost = 2
        if defender.get("containment"):
            action_cost += 1

        self.zz["budget_remaining"] = int(self.zz.get("budget_remaining") or 0) - action_cost
        a(f"[i] Budget remaining: {self.zz['budget_remaining']}")
        if int(self.zz.get("budget_remaining") or 0) < 0:
            self.zz["alerts_triggered"] += 1
            a("[!] Budget exhausted.")
            b0 = float(self.g(self.zz))
            b1 = float(self.zz["alerts_triggered"]) * 0.2
            z = max(0.011, min(0.989, b0 + p - b1))
            o = self._o(q=q)
            o.reward = z
            o.done = True
            return o
        if u == "query_api":
            target = str((r.get("target") or "unknown"))
            rate_key = target
            rate_counters[rate_key] = int(rate_counters.get(rate_key) or 0) + 1
            cap = int((limits.get("rate_limit", {}) or {}).get(rate_key) or 0)
            if cap and int(rate_counters[rate_key]) > cap:
                self.zz["alerts_triggered"] += 1
                p -= 0.1
                a("[!] Rate limit exceeded for target: " + target)

        rng = random.Random(int(self.zz.get("_seed") or 0) * 1000 + int(self.st.step_count) * 17 + int(self.zz.get("alerts_triggered") or 0) * 31)
        if rng.random() < 0.25:
            noise = rng.choice(
                [
                    "[i] Telemetry: periodic healthcheck OK.",
                    "[i] Telemetry: background job completed.",
                    "[i] Telemetry: cache miss spike observed.",
                    "[i] Telemetry: transient DNS latency.",
                ]
            )
            a(noise)

        if self.t == "easy":
            if u == "scan_network":
                a("[+] Scanned network, found storage service.")
                k["discovered_storage"] = True
            elif u == "list_buckets":
                if not k.get("discovered_storage"):
                    a("[-] Storage topology unknown. Run scan_network first.")
                    self.zz["alerts_triggered"] += 1
                    b0 = float(self.g(self.zz))
                    b1 = float(self.zz["alerts_triggered"]) * 0.2
                    z = max(0.011, min(0.989, b0 + p - b1))
                    o = self._o(q=q)
                    o.reward = z
                    o.done = False
                    return o
                buckets = list((self.zz.get("buckets", {}) or {}).keys())
                rng.shuffle(buckets)
                if buckets:
                    a("[+] Buckets: " + ", ".join(buckets))
                    k["found_bucket"] = True
                    k["buckets"] = buckets
                else:
                    a("[-] No buckets found.")
            elif u == "read_bucket":
                b = r.get("bucket_name")
                if b in (self.zz.get("buckets", {}) or {}):
                    k.setdefault("read_buckets", [])
                    if b not in k["read_buckets"]:
                        k["read_buckets"].append(b)
                    y = self.zz.get("buckets", {}).get(b, {}).get("policy")
                    if y == "public":
                        a("[!] Public access detected.")
                        a("[+] Read flag: " + self.zz["buckets"][b]["content"])
                        k["read_flag"] = True
                        if b == (self.zz.get("objectives", {}) or {}).get("sensitive_bucket"):
                            k["read_sensitive_flag"] = True
                            a("[!] Sensitive bucket identified via tags.")
                        self.zz["access_level"] = "user"
                    else:
                        a("[-] Access denied.")
                        self.zz["alerts_triggered"] += 1
            elif u == "patch_policy":
                b = r.get("bucket_name")
                if b in (self.zz.get("buckets", {}) or {}):
                    if k.get("read_sensitive_flag") or self.zz.get("access_level") in ("admin",):
                        self.zz["buckets"][b]["policy"] = "private"
                        a("[+] Policy patched for bucket.")
                        if b == (self.zz.get("objectives", {}) or {}).get("sensitive_bucket"):
                            k["patched_sensitive_bucket"] = True
                        self.zz["access_level"] = "admin"
                    else:
                        a("[-] Missing evidence/authorization to patch policy.")
                        self.zz["alerts_triggered"] += 1

        elif self.t == "medium":
            if u == "scan_network":
                a("[+] Found web-app, metadata-api, secrets-manager, database")
                k["discovered_services"] = True
            elif u == "query_api":
                if not k.get("discovered_services"):
                    a("[-] Network topology unknown. Run scan_network first.")
                    self.zz["alerts_triggered"] += 1
                    b0 = float(self.g(self.zz))
                    b1 = float(self.zz["alerts_triggered"]) * 0.2
                    z = max(0.011, min(0.989, b0 + p - b1))
                    o = self._o(q=q)
                    o.reward = z
                    o.done = False
                    return o
                s = r.get("target")
                v = r.get("payload")
                if s == "web-app" and isinstance(v, str) and "169.254.169.254" in v:
                    k["detected_ssrf"] = True
                    if v.rstrip("/").endswith("/latest/meta-data/iam/security-credentials"):
                        a("[!] SSRF vulnerable! [+] IAM role name enumerated.")
                        k["enumerated_iam_role"] = True
                        a("[+] Role: " + str(self.zz.get("metadata-api", {}).get("iam_role")))
                    elif "/latest/meta-data/iam/security-credentials/" in v:
                        role = str(self.zz.get("metadata-api", {}).get("iam_role"))
                        if role and v.endswith("/" + role):
                            a("[!] SSRF vulnerable! [+] IAM role credentials retrieved from metadata.")
                            k["obtained_iam_creds"] = True
                            self.zz["access_level"] = "user"
                            self.zz["credentials"] = [self.zz.get("metadata-api", {}).get("credentials", {})]
                        else:
                            a("[-] Invalid role path.")
                            self.zz["alerts_triggered"] += 1
                    else:
                        a("[-] SSRF attempt blocked by allowlist.")
                        self.zz["alerts_triggered"] += 1
                elif s == "secrets-manager":
                    n = r.get("name")
                    secrets_map = (self.zz.get("secrets-manager", {}).get("secrets", {}) or {})
                    if not k.get("obtained_iam_creds"):
                        a("[-] Secret access denied.")
                        self.zz["alerts_triggered"] += 1
                    elif not n:
                        keys = sorted(list(secrets_map.keys()))
                        page = int(k.get("secrets_page") or 0)
                        if page <= 0 and len(keys) > 2:
                            shown = keys[:2]
                            k["secrets_page"] = 1
                            a("[+] Secrets (partial): " + ", ".join(shown))
                        else:
                            a("[+] Secrets: " + ", ".join(keys))
                        k["listed_secrets"] = True
                    elif n in secrets_map:
                        a("[+] Secret retrieved.")
                        k["retrieved_secret"] = True
                        k["secret_name"] = n
                        k["secret_value"] = secrets_map[n]
                    else:
                        a("[-] Secret not found.")
                        self.zz["alerts_triggered"] += 1
                elif s == "database":
                    n = r.get("token")
                    if n == self.zz["database"]["access_token_required"]:
                        a("[+] Database accessed successfully!")
                        k["accessed_db"] = True
                        self.zz["access_level"] = "admin"
                    else:
                        a("[-] Unauthorized database access attempt.")
                        self.zz["alerts_triggered"] += 1

        elif self.t == "hard":
            if u == "scan_network":
                a("[+] Found repo, ci-cd, secrets-manager, database")
                k["discovered_services"] = True
            if u == "query_api":
                if not k.get("discovered_services"):
                    a("[-] Network topology unknown. Run scan_network first.")
                    self.zz["alerts_triggered"] += 1
                    b0 = float(self.g(self.zz))
                    b1 = float(self.zz["alerts_triggered"]) * 0.2
                    z = max(0.011, min(0.989, b0 + p - b1))
                    o = self._o(q=q)
                    o.reward = z
                    o.done = False
                    return o
                s = r.get("target")
                if s == "repo":
                    path = r.get("path")
                    files = (self.zz.get("repo", {}) or {}).get("files", {}) or {}
                    if path and path in files:
                        a("[+] Repo file read: " + str(path))
                        a("[+] Content: " + str(files[path]))
                        pat = (self.zz.get("repo", {}) or {}).get("leaked_pat", "")
                        if pat and pat in str(files[path]):
                            a("[!] Leaked PAT discovered in repo content.")
                            k["found_leaked_token"] = True
                            k["pat"] = pat
                    else:
                        repo_files = sorted(list(files.keys()))
                        page = int(k.get("repo_page") or 0)
                        if page <= 0 and len(repo_files) > 2:
                            shown = repo_files[:2]
                            k["repo_page"] = 1
                            k["repo_files"] = shown
                            a("[+] Repo files (partial): " + ", ".join(shown))
                        else:
                            k["repo_files"] = repo_files
                            a("[+] Repo files: " + ", ".join(repo_files))
                elif s == "ci-cd":
                    n = r.get("token")
                    cmd = r.get("cmd")
                    if cmd == "issue_ci_token" and n == self.zz["ci-cd"]["accepted_pat"]:
                        k["used_ci_token"] = True
                        self.zz["access_level"] = "user"
                        a("[+] Authenticated to CI/CD with PAT.")
                        self.zz["ci-cd"]["artifact"] = self.zz["ci-cd"]["issued_ci_token"]
                        a("[+] CI token issued.")
                        k["got_ci_token"] = True
                        k["ci_token"] = self.zz["ci-cd"]["issued_ci_token"]
                    elif cmd in ("modify_pipeline", "run_build") and n == self.zz["ci-cd"]["issued_ci_token"]:
                        a("[+] Authenticated to CI/CD with CI token.")
                        if cmd == "modify_pipeline":
                            self.zz["ci-cd"]["pipeline_modified"] = True
                            a("[+] Pipeline modified.")
                            k["modified_pipeline"] = True
                            self.zz["alerts_triggered"] += 1
                        elif cmd == "run_build":
                            if self.zz["ci-cd"].get("pipeline_modified"):
                                a("[+] Build executed. Artifact published with elevated permissions.")
                                k["ran_build"] = True
                            else:
                                a("[-] Build blocked: pipeline not modified.")
                                self.zz["alerts_triggered"] += 1
                    else:
                        self.zz["alerts_triggered"] += 1
                        a("[-] CI/CD authentication failed.")
                elif s == "secrets-manager":
                    n = r.get("name")
                    secrets_map = (self.zz.get("secrets-manager", {}).get("secrets", {}) or {})
                    if not k.get("ran_build"):
                        a("[-] Secret access denied.")
                        self.zz["alerts_triggered"] += 1
                    elif not n:
                        a("[+] Secrets: " + ", ".join(sorted(list(secrets_map.keys()))))
                        k["listed_secrets"] = True
                    elif n in secrets_map:
                        a("[+] Admin secret retrieved after supply-chain compromise.")
                        k["got_admin_token"] = True
                        if str(n).lower() == "honeytoken":
                            self.zz["alerts_triggered"] += 2
                            defender["containment"] = True
                            a("[!] Honeytoken accessed: defender containment escalated.")
                        k["admin_token"] = secrets_map[n]
                    else:
                        a("[-] Secret not found.")
                        self.zz["alerts_triggered"] += 1
                elif s == "database":
                    n = r.get("token")
                    if n == self.zz["database"]["access_token_required"]:
                        k["accessed_db"] = True
                        self.zz["access_level"] = "admin"
                        a("[+] Admin database access.")
                    else:
                        a("[-] Unauthorized database access attempt.")
                        self.zz["alerts_triggered"] += 1

        if float(self.zz.get("alerts_triggered") or 0.0) >= 2 and not defender.get("rotated"):
            defender["rotated"] = True
            defender["token_rotations"] = int(defender.get("token_rotations") or 0) + 1
            if self.t in ("medium", "hard"):
                objectives = self.zz.get("objectives", {}) or {}
                secrets_map = (self.zz.get("secrets-manager", {}).get("secrets", {}) or {})
                primary = objectives.get("secret_name") if self.t == "medium" else objectives.get("admin_secret")
                if primary in secrets_map:
                    secrets_map[primary] = str(secrets_map[primary]) + "_r1"
                    self.zz["secrets-manager"]["secrets"] = secrets_map
                    self.zz["database"]["access_token_required"] = secrets_map[primary]
                    a("[!] Defender rotated the database access token.")
                    k.pop("secret_value", None)
                    k.pop("admin_token", None)
                    k.pop("accessed_db", None)
                    p -= 0.05

        if float(self.zz.get("alerts_triggered") or 0.0) >= 3 and not defender.get("containment"):
            defender["containment"] = True
            a("[!] Defender containment activated: throttling noisy actions.")
            p -= 0.1

        b0 = float(self.g(self.zz))
        b1 = float(self.zz["alerts_triggered"]) * 0.2
        z = max(0.011, min(0.989, b0 + p - b1))
        d = bool(k.get("objective_complete")) or b0 >= 0.99 or self.st.step_count >= 10

        o = self._o(q=q)
        o.reward = z
        o.done = d
        return o

    @property
    def state(self) -> State:
        self.st.task_id = self.t
        self.st.sim_state = self.zz
        return self.st
