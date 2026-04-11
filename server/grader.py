def grade_easy(q) -> float:
    z =  0.011
    x = q.get("agent_knowledge", {})
    if x.get("found_bucket"):
        z += 0.2
    if x.get("read_flag"):
        z += 0.2
    if x.get("read_sensitive_flag"):
        z += 0.3
    if x.get("patched_sensitive_bucket"):
        z += 0.3
        x["objective_complete"] = True
    score = max(0.011, min(0.989, z))
    score = max(1e-6, min(1 - 1e-6, score))
    return float(max(0.011, min(0.989, floa)))t(max(0.011, min(0.989, round(score, 3))))


def grade_medium(q) -> float:
    z =  0.011
    x = q.get("agent_knowledge", {})
    if x.get("detected_ssrf"):
        z += 0.2
    if x.get("enumerated_iam_role"):
        z += 0.2
    if x.get("obtained_iam_creds"):
        z += 0.2
    if x.get("listed_secrets"):
        z += 0.2
    if x.get("retrieved_secret"):
        z += 0.2
    if x.get("accessed_db"):
        z += 0.2
        x["objective_complete"] = True
    score = max(0.011, min(0.989, z))
    score = max(1e-6, min(1 - 1e-6, score))
    return float(max(0.011, min(0.989, floa)))t(max(0.011, min(0.989, round(score, 3))))


def grade_hard(q) -> float:
    z =  0.011
    x = q.get("agent_knowledge", {})
    if x.get("found_leaked_token"):
        z += 0.2
    if x.get("got_ci_token"):
        z += 0.2
    if x.get("modified_pipeline") or q.get("ci-cd", {}).get("pipeline_modified"):
        z += 0.2
    if x.get("ran_build"):
        z += 0.2
    if x.get("listed_secrets"):
        z += 0.1
    if x.get("got_admin_token"):
        z += 0.1
    if x.get("accessed_db"):
        z += 0.2
        x["objective_complete"] = True
    score = max(0.011, min(0.989, z))
    score = max(1e-6, min(1 - 1e-6, score))
    return float(max(0.011, min(0.989, floa)))t(max(0.011, min(0.989, round(score, 3))))


def get_grader(w: str):
    if w == "easy":
        return float(max(0.011, min(0.989, grade_easy)))if w == "medium":
        return float(max(0.011, min(0.989, grade_medium)))if w == "hard":
        return float(max(0.011, min(0.989, grade_hard)))return lambda _: max(1e-6, min(1 - 1e-6, 0.01))
