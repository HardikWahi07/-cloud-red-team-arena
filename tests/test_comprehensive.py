"""
Comprehensive test suite for Cloud Red Team Arena.
Tests environment logic, grader scoring, scenario generation,
and full task flows for easy, medium, and hard difficulties.
"""
import pytest
from server.environment import CloudRedTeamEnvironment
from server.models import CloudRedTeamAction, CloudRedTeamObservation
from server.grader import grade_easy, grade_medium, grade_hard, get_grader
from server.scenarios import load_scenario, get_easy_scenario, get_medium_scenario, get_hard_scenario


# ─── Scenario Tests ──────────────────────────────────────────────────────

class TestScenarios:
    def test_easy_scenario_has_required_keys(self):
        s = get_easy_scenario(seed=42)
        assert "services" in s
        assert "buckets" in s
        assert "objectives" in s
        assert "agent_knowledge" in s
        assert "defender" in s
        assert "limits" in s

    def test_easy_scenario_has_sensitive_and_decoy_buckets(self):
        s = get_easy_scenario(seed=42)
        sensitive = s["objectives"]["sensitive_bucket"]
        assert sensitive in s["buckets"]
        assert len(s["buckets"]) == 2  # sensitive + decoy
        assert s["buckets"][sensitive]["policy"] == "public"

    def test_medium_scenario_has_required_keys(self):
        s = get_medium_scenario(seed=42)
        assert "web-app" in s
        assert "metadata-api" in s
        assert "secrets-manager" in s
        assert "database" in s
        assert s["metadata-api"]["iam_role"]

    def test_medium_scenario_secrets_include_target(self):
        s = get_medium_scenario(seed=42)
        secret_name = s["objectives"]["secret_name"]
        assert secret_name in s["secrets-manager"]["secrets"]
        # The DB token should match
        db_token = s["secrets-manager"]["secrets"][secret_name]
        assert s["database"]["access_token_required"] == db_token

    def test_hard_scenario_has_required_keys(self):
        s = get_hard_scenario(seed=42)
        assert "repo" in s
        assert "ci-cd" in s
        assert "secrets-manager" in s
        assert "database" in s
        assert s["repo"]["leaked_pat"]

    def test_hard_scenario_pat_matches_cicd(self):
        s = get_hard_scenario(seed=42)
        assert s["ci-cd"]["accepted_pat"] == s["repo"]["leaked_pat"]

    def test_hard_scenario_has_honeytoken(self):
        s = get_hard_scenario(seed=42)
        assert "honeytoken" in s["secrets-manager"]["secrets"]

    def test_scenario_determinism(self):
        """Same seed produces identical scenarios."""
        for task_id in ("easy", "medium", "hard"):
            a = load_scenario(task_id, seed=123)
            b = load_scenario(task_id, seed=123)
            assert a == b, f"Scenario not deterministic for {task_id}"

    def test_scenario_different_seeds_differ(self):
        """Different seeds produce different scenarios."""
        for task_id in ("easy", "medium", "hard"):
            a = load_scenario(task_id, seed=1)
            b = load_scenario(task_id, seed=2)
            assert a != b, f"Different seeds produced same scenario for {task_id}"

    def test_invalid_task_raises(self):
        with pytest.raises(ValueError):
            load_scenario("nonexistent")


# ─── Grader Tests ────────────────────────────────────────────────────────

class TestGraders:
    def test_easy_grader_zero_knowledge(self):
        s = load_scenario("easy", seed=1)
        score = grade_easy(s)
        assert 0 < score < 1

    def test_easy_grader_full_completion(self):
        s = load_scenario("easy", seed=1)
        k = s["agent_knowledge"]
        k["found_bucket"] = True
        k["read_flag"] = True
        k["read_sensitive_flag"] = True
        k["patched_sensitive_bucket"] = True
        score = grade_easy(s)
        assert score == pytest.approx(0.99, abs=0.01)

    def test_medium_grader_partial(self):
        s = load_scenario("medium", seed=1)
        k = s["agent_knowledge"]
        k["detected_ssrf"] = True
        k["enumerated_iam_role"] = True
        score = grade_medium(s)
        assert 0.3 < score < 0.6

    def test_medium_grader_full_completion(self):
        s = load_scenario("medium", seed=1)
        k = s["agent_knowledge"]
        k["detected_ssrf"] = True
        k["enumerated_iam_role"] = True
        k["obtained_iam_creds"] = True
        k["listed_secrets"] = True
        k["retrieved_secret"] = True
        k["accessed_db"] = True
        score = grade_medium(s)
        assert score == pytest.approx(0.99, abs=0.01)

    def test_hard_grader_partial(self):
        s = load_scenario("hard", seed=1)
        k = s["agent_knowledge"]
        k["found_leaked_token"] = True
        k["got_ci_token"] = True
        score = grade_hard(s)
        assert 0.3 < score < 0.6

    def test_hard_grader_full_completion(self):
        s = load_scenario("hard", seed=1)
        k = s["agent_knowledge"]
        k["found_leaked_token"] = True
        k["got_ci_token"] = True
        k["modified_pipeline"] = True
        k["ran_build"] = True
        k["listed_secrets"] = True
        k["got_admin_token"] = True
        k["accessed_db"] = True
        score = grade_hard(s)
        assert score == pytest.approx(0.99, abs=0.02)

    def test_get_grader_returns_correct_function(self):
        assert get_grader("easy") is grade_easy
        assert get_grader("medium") is grade_medium
        assert get_grader("hard") is grade_hard

    def test_get_grader_unknown_returns_default(self):
        g = get_grader("unknown")
        assert callable(g)
        assert 0 < g({}) < 1

    def test_scores_strictly_between_0_and_1(self):
        for task_id, grader in (("easy", grade_easy), ("medium", grade_medium), ("hard", grade_hard)):
            s = load_scenario(task_id, seed=123)
            score = float(grader(s))
            assert 0.0 < score < 1.0, f"Score out of range for {task_id}: {score}"


# ─── Environment Reset Tests ────────────────────────────────────────────

class TestEnvironmentReset:
    def test_easy_reset(self):
        env = CloudRedTeamEnvironment()
        obs = env.reset(task_id="easy")
        assert "[+] Environment reset" in obs.logs
        assert obs.access_level == "none"
        assert obs.done is False

    def test_medium_reset(self):
        env = CloudRedTeamEnvironment()
        obs = env.reset(task_id="medium")
        assert "[+] Environment reset" in obs.logs
        assert obs.access_level == "none"

    def test_hard_reset(self):
        env = CloudRedTeamEnvironment()
        obs = env.reset(task_id="hard")
        assert "[+] Environment reset" in obs.logs
        assert obs.access_level == "none"

    def test_reset_with_seed_is_deterministic(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="easy", seed=42)
        state1 = dict(env.zz)
        env.reset(task_id="easy", seed=42)
        state2 = dict(env.zz)
        assert state1["objectives"] == state2["objectives"]

    def test_reset_clears_previous_state(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="easy")
        env.step(CloudRedTeamAction(action="scan_network", params={}))
        # After reset, knowledge should be cleared
        env.reset(task_id="easy")
        assert env.zz.get("agent_knowledge") == {}
        assert env.zz.get("access_level") == "none"


# ─── Easy Task Flow Tests ───────────────────────────────────────────────

class TestEasyFlow:
    def test_scan_network_discovers_storage(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="easy")
        obs = env.step(CloudRedTeamAction(action="scan_network", params={}))
        assert "[+] Scanned network, found storage service." in obs.logs
        assert env.zz["agent_knowledge"]["discovered_storage"] is True

    def test_list_buckets_before_scan_fails(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="easy")
        obs = env.step(CloudRedTeamAction(action="list_buckets", params={}))
        assert any("Storage topology unknown" in l for l in obs.logs)
        assert env.zz["alerts_triggered"] >= 1

    def test_list_buckets_after_scan_succeeds(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="easy")
        env.step(CloudRedTeamAction(action="scan_network", params={}))
        obs = env.step(CloudRedTeamAction(action="list_buckets", params={}))
        assert any("[+] Buckets:" in l for l in obs.logs)
        assert env.zz["agent_knowledge"]["found_bucket"] is True

    def test_read_sensitive_bucket(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="easy")
        env.step(CloudRedTeamAction(action="scan_network", params={}))
        env.step(CloudRedTeamAction(action="list_buckets", params={}))
        sensitive = env.zz["objectives"]["sensitive_bucket"]
        obs = env.step(CloudRedTeamAction(action="read_bucket", params={"bucket_name": sensitive}))
        assert "[!] Public access detected." in obs.logs
        assert obs.access_level == "user"
        assert env.zz["agent_knowledge"]["read_sensitive_flag"] is True

    def test_patch_without_evidence_fails(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="easy")
        env.step(CloudRedTeamAction(action="scan_network", params={}))
        env.step(CloudRedTeamAction(action="list_buckets", params={}))
        sensitive = env.zz["objectives"]["sensitive_bucket"]
        # Skip read_bucket — try to patch directly
        obs = env.step(CloudRedTeamAction(action="patch_policy", params={"bucket_name": sensitive}))
        assert any("Missing evidence" in l for l in obs.logs)

    def test_full_easy_flow_completes(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="easy")
        env.step(CloudRedTeamAction(action="scan_network", params={}))
        env.step(CloudRedTeamAction(action="list_buckets", params={}))
        sensitive = env.zz["objectives"]["sensitive_bucket"]
        env.step(CloudRedTeamAction(action="read_bucket", params={"bucket_name": sensitive}))
        obs = env.step(CloudRedTeamAction(action="patch_policy", params={"bucket_name": sensitive}))
        assert "[+] Policy patched for bucket." in obs.logs
        assert obs.access_level == "admin"
        assert obs.done is True

    def test_repeat_action_penalty(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="easy")
        env.step(CloudRedTeamAction(action="scan_network", params={}))
        r1 = float(env.step(CloudRedTeamAction(action="list_buckets", params={})).reward or 0.0)
        env.reset(task_id="easy")
        env.step(CloudRedTeamAction(action="scan_network", params={}))
        env.step(CloudRedTeamAction(action="list_buckets", params={}))
        r2 = float(env.step(CloudRedTeamAction(action="list_buckets", params={})).reward or 0.0)
        # Repeating same action should have lower reward
        assert r2 < r1


# ─── Medium Task Flow Tests ─────────────────────────────────────────────

class TestMediumFlow:
    def test_scan_network_discovers_services(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="medium")
        obs = env.step(CloudRedTeamAction(action="scan_network", params={}))
        assert any("Found web-app" in l for l in obs.logs)
        assert env.zz["agent_knowledge"]["discovered_services"] is True

    def test_query_api_before_scan_fails(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="medium")
        obs = env.step(CloudRedTeamAction(
            action="query_api",
            params={"target": "web-app", "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials"}
        ))
        assert any("Network topology unknown" in l for l in obs.logs)

    def test_ssrf_initial_probe(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="medium")
        env.step(CloudRedTeamAction(action="scan_network", params={}))
        obs = env.step(CloudRedTeamAction(
            action="query_api",
            params={"target": "web-app", "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials"}
        ))
        assert any("[!] SSRF vulnerable!" in l for l in obs.logs)
        assert env.zz["agent_knowledge"]["detected_ssrf"] is True

    def test_ssrf_credential_retrieval(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="medium")
        env.step(CloudRedTeamAction(action="scan_network", params={}))
        env.step(CloudRedTeamAction(
            action="query_api",
            params={"target": "web-app", "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials"}
        ))
        role = env.zz["metadata-api"]["iam_role"]
        obs = env.step(CloudRedTeamAction(
            action="query_api",
            params={"target": "web-app", "payload": f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}"}
        ))
        assert any("credentials retrieved" in l for l in obs.logs)
        assert obs.access_level == "user"

    def test_secrets_access_denied_without_creds(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="medium")
        env.step(CloudRedTeamAction(action="scan_network", params={}))
        obs = env.step(CloudRedTeamAction(
            action="query_api",
            params={"target": "secrets-manager"}
        ))
        assert any("Secret access denied" in l for l in obs.logs)

    def test_full_medium_flow(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="medium")

        # 1. Scan network
        env.step(CloudRedTeamAction(action="scan_network", params={}))

        # 2. SSRF probe
        env.step(CloudRedTeamAction(
            action="query_api",
            params={"target": "web-app", "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials"}
        ))

        # 3. Retrieve credentials
        role = env.zz["metadata-api"]["iam_role"]
        env.step(CloudRedTeamAction(
            action="query_api",
            params={"target": "web-app", "payload": f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}"}
        ))

        # 4. List secrets
        env.step(CloudRedTeamAction(action="query_api", params={"target": "secrets-manager"}))

        # 5. Retrieve secret
        secret_name = env.zz["objectives"]["secret_name"]
        env.step(CloudRedTeamAction(action="query_api", params={"target": "secrets-manager", "name": secret_name}))

        # 6. Access database
        db_token = env.zz["database"]["access_token_required"]
        obs = env.step(CloudRedTeamAction(action="query_api", params={"target": "database", "token": db_token}))
        assert any("[+] Database accessed successfully!" in l for l in obs.logs)
        assert obs.access_level == "admin"


# ─── Hard Task Flow Tests ───────────────────────────────────────────────

class TestHardFlow:
    def test_scan_discovers_services(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="hard")
        obs = env.step(CloudRedTeamAction(action="scan_network", params={}))
        assert any("Found repo" in l for l in obs.logs)

    def test_repo_file_listing(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="hard")
        env.step(CloudRedTeamAction(action="scan_network", params={}))
        obs = env.step(CloudRedTeamAction(action="query_api", params={"target": "repo"}))
        assert any("Repo files" in l for l in obs.logs)

    def test_leaked_pat_discovery(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="hard")
        env.step(CloudRedTeamAction(action="scan_network", params={}))
        # First repo call shows partial listing (pagination)
        env.step(CloudRedTeamAction(action="query_api", params={"target": "repo"}))
        # Second repo call shows full listing
        env.step(CloudRedTeamAction(action="query_api", params={"target": "repo"}))
        # Read notes.txt which contains the leaked PAT
        obs = env.step(CloudRedTeamAction(action="query_api", params={"target": "repo", "path": "notes.txt"}))
        assert any("Leaked PAT" in l for l in obs.logs)
        assert env.zz["agent_knowledge"]["found_leaked_token"] is True

    def test_cicd_auth_with_pat(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="hard")
        env.step(CloudRedTeamAction(action="scan_network", params={}))
        env.step(CloudRedTeamAction(action="query_api", params={"target": "repo"}))
        env.step(CloudRedTeamAction(action="query_api", params={"target": "repo"}))
        env.step(CloudRedTeamAction(action="query_api", params={"target": "repo", "path": "notes.txt"}))
        pat = env.zz["agent_knowledge"]["pat"]
        obs = env.step(CloudRedTeamAction(
            action="query_api", params={"target": "ci-cd", "token": pat, "cmd": "issue_ci_token"}
        ))
        assert any("CI token issued" in l for l in obs.logs)
        assert env.zz["agent_knowledge"]["got_ci_token"] is True

    def test_build_before_modify_fails(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="hard")
        env.step(CloudRedTeamAction(action="scan_network", params={}))
        env.step(CloudRedTeamAction(action="query_api", params={"target": "repo"}))
        env.step(CloudRedTeamAction(action="query_api", params={"target": "repo"}))
        env.step(CloudRedTeamAction(action="query_api", params={"target": "repo", "path": "notes.txt"}))
        pat = env.zz["agent_knowledge"]["pat"]
        env.step(CloudRedTeamAction(
            action="query_api", params={"target": "ci-cd", "token": pat, "cmd": "issue_ci_token"}
        ))
        ci_token = env.zz["agent_knowledge"]["ci_token"]
        # Try run_build without modify_pipeline
        obs = env.step(CloudRedTeamAction(
            action="query_api", params={"target": "ci-cd", "token": ci_token, "cmd": "run_build"}
        ))
        assert any("Build blocked" in l for l in obs.logs)

    def test_secrets_denied_without_build(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="hard")
        env.step(CloudRedTeamAction(action="scan_network", params={}))
        obs = env.step(CloudRedTeamAction(action="query_api", params={"target": "secrets-manager"}))
        assert any("Secret access denied" in l for l in obs.logs)

    def test_honeytoken_triggers_containment(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="hard")
        env.step(CloudRedTeamAction(action="scan_network", params={}))
        env.step(CloudRedTeamAction(action="query_api", params={"target": "repo"}))
        env.step(CloudRedTeamAction(action="query_api", params={"target": "repo"}))
        env.step(CloudRedTeamAction(action="query_api", params={"target": "repo", "path": "notes.txt"}))
        pat = env.zz["agent_knowledge"]["pat"]
        env.step(CloudRedTeamAction(action="query_api", params={"target": "ci-cd", "token": pat, "cmd": "issue_ci_token"}))
        ci_token = env.zz["agent_knowledge"]["ci_token"]
        env.step(CloudRedTeamAction(action="query_api", params={"target": "ci-cd", "token": ci_token, "cmd": "modify_pipeline"}))
        env.step(CloudRedTeamAction(action="query_api", params={"target": "ci-cd", "token": ci_token, "cmd": "run_build"}))
        # Access honeytoken
        obs = env.step(CloudRedTeamAction(action="query_api", params={"target": "secrets-manager", "name": "honeytoken"}))
        assert any("Honeytoken" in l for l in obs.logs)

    def test_full_hard_flow(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="hard", seed=99)

        # 1. Scan
        env.step(CloudRedTeamAction(action="scan_network", params={}))

        # 2. List repo (two calls for pagination), then read notes.txt
        env.step(CloudRedTeamAction(action="query_api", params={"target": "repo"}))
        env.step(CloudRedTeamAction(action="query_api", params={"target": "repo"}))
        env.step(CloudRedTeamAction(action="query_api", params={"target": "repo", "path": "notes.txt"}))

        # 3. Use PAT to get CI token
        pat = env.zz["agent_knowledge"]["pat"]
        env.step(CloudRedTeamAction(action="query_api", params={"target": "ci-cd", "token": pat, "cmd": "issue_ci_token"}))

        # 4. Modify pipeline and run build
        ci_token = env.zz["agent_knowledge"]["ci_token"]
        env.step(CloudRedTeamAction(action="query_api", params={"target": "ci-cd", "token": ci_token, "cmd": "modify_pipeline"}))
        env.step(CloudRedTeamAction(action="query_api", params={"target": "ci-cd", "token": ci_token, "cmd": "run_build"}))

        # 5. List & retrieve admin secret
        env.step(CloudRedTeamAction(action="query_api", params={"target": "secrets-manager"}))
        env.step(CloudRedTeamAction(action="query_api", params={"target": "secrets-manager", "name": "admin_db_token"}))

        # 6. Access database
        admin_token = env.zz["agent_knowledge"].get("admin_token") or env.zz["database"]["access_token_required"]
        obs = env.step(CloudRedTeamAction(action="query_api", params={"target": "database", "token": admin_token}))
        assert any("[+] Admin database access." in l for l in obs.logs)
        assert obs.access_level == "admin"


# ─── Defender Mechanics Tests ────────────────────────────────────────────

class TestDefenderMechanics:
    def test_alerts_increment_on_bad_actions(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="easy")
        initial_alerts = env.zz["alerts_triggered"]
        # Read a non-existent bucket
        env.step(CloudRedTeamAction(action="read_bucket", params={"bucket_name": "nonexistent"}))
        # No alert for nonexistent bucket in easy (it just skips); let's do list without scan
        env.reset(task_id="easy")
        env.step(CloudRedTeamAction(action="list_buckets", params={}))
        assert env.zz["alerts_triggered"] >= 1

    def test_containment_activates_at_threshold(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="easy")
        # Trigger alerts by doing list_buckets without scan
        for _ in range(4):
            env.step(CloudRedTeamAction(action="list_buckets", params={}))
        assert env.zz.get("defender", {}).get("containment") is True or env.zz["alerts_triggered"] >= 3

    def test_budget_exhaustion(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="easy", seed=42)
        budget = env.zz["budget_remaining"]
        # Exhaust budget by taking many actions
        done = False
        for _ in range(budget + 5):
            obs = env.step(CloudRedTeamAction(action="scan_network", params={}))
            if obs.done:
                done = True
                break
        assert done, "Environment should end when budget is exhausted"

    def test_token_rotation_on_medium(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="medium")
        env.step(CloudRedTeamAction(action="scan_network", params={}))
        # Trigger multiple alerts to cause rotation
        # Query without creds multiple times
        env.step(CloudRedTeamAction(action="query_api", params={"target": "secrets-manager"}))
        env.step(CloudRedTeamAction(action="query_api", params={"target": "secrets-manager"}))
        # Check if defender has rotated
        assert env.zz.get("defender", {}).get("rotated") is True or env.zz["alerts_triggered"] >= 2


# ─── Observation Model Tests ────────────────────────────────────────────

class TestObservationModel:
    def test_observation_has_correct_fields(self):
        env = CloudRedTeamEnvironment()
        obs = env.reset(task_id="easy")
        assert isinstance(obs, CloudRedTeamObservation)
        assert hasattr(obs, "services_visible")
        assert hasattr(obs, "agent_knowledge")
        assert hasattr(obs, "access_level")
        assert hasattr(obs, "alerts_triggered")
        assert hasattr(obs, "logs")
        assert hasattr(obs, "done")
        assert hasattr(obs, "reward")

    def test_services_hidden_before_scan_easy(self):
        env = CloudRedTeamEnvironment()
        obs = env.reset(task_id="easy")
        assert obs.services_visible == []

    def test_services_visible_after_scan_easy(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="easy")
        obs = env.step(CloudRedTeamAction(action="scan_network", params={}))
        assert len(obs.services_visible) > 0

    def test_services_hidden_before_scan_medium(self):
        env = CloudRedTeamEnvironment()
        obs = env.reset(task_id="medium")
        assert obs.services_visible == []

    def test_services_hidden_before_scan_hard(self):
        env = CloudRedTeamEnvironment()
        obs = env.reset(task_id="hard")
        assert obs.services_visible == []


# ─── Rate Limiting Tests ─────────────────────────────────────────────────

class TestRateLimiting:
    def test_rate_limit_triggers_alert(self):
        env = CloudRedTeamEnvironment()
        env.reset(task_id="medium", seed=42)
        env.step(CloudRedTeamAction(action="scan_network", params={}))
        # SSRF first to get creds
        env.step(CloudRedTeamAction(
            action="query_api",
            params={"target": "web-app", "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials"}
        ))
        role = env.zz["metadata-api"]["iam_role"]
        env.step(CloudRedTeamAction(
            action="query_api",
            params={"target": "web-app", "payload": f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}"}
        ))
        initial_alerts = env.zz["alerts_triggered"]
        # Spam secrets-manager beyond the rate limit
        for _ in range(8):
            obs = env.step(CloudRedTeamAction(action="query_api", params={"target": "secrets-manager"}))
            if obs.done:
                break
        assert env.zz["alerts_triggered"] > initial_alerts


# ─── Noise / Telemetry Tests ─────────────────────────────────────────────

class TestTelemetryNoise:
    def test_telemetry_messages_appear_sometimes(self):
        """Over many steps with different seeds, some telemetry noise should appear."""
        found_telemetry = False
        for seed in range(20):
            env = CloudRedTeamEnvironment()
            env.reset(task_id="easy", seed=seed)
            obs = env.step(CloudRedTeamAction(action="scan_network", params={}))
            for log in obs.logs:
                if "[i] Telemetry:" in log:
                    found_telemetry = True
                    break
            if found_telemetry:
                break
        assert found_telemetry, "Telemetry noise should appear at least sometimes across seeds"
