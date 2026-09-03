from fstec_lint.checks import dockerfile_checks as dc


def _inst(instruction, args, line=1):
    return {"instruction": instruction, "args": args, "line": line}


def test_missing_user_flagged():
    instructions = [_inst("FROM", "node:20"), _inst("CMD", '["node", "app.js"]')]
    assert len(dc.check_missing_user(instructions)) == 1


def test_user_present_ok():
    instructions = [_inst("FROM", "node:20"), _inst("USER", "appuser")]
    assert dc.check_missing_user(instructions) == []


def test_missing_user_checks_last_stage_only():
    instructions = [
        _inst("FROM", "golang:1.22 AS build"),
        _inst("RUN", "go build -o app"),
        _inst("FROM", "gcr.io/distroless/base"),
        _inst("USER", "nonroot"),
    ]
    assert dc.check_missing_user(instructions) == []


def test_add_remote_url_flagged():
    instructions = [_inst("ADD", "https://example.com/agent.tar.gz /opt/agent.tar.gz")]
    assert len(dc.check_add_remote_url(instructions)) == 1


def test_add_local_file_ok():
    instructions = [_inst("ADD", "app.tar.gz /opt/app.tar.gz")]
    assert dc.check_add_remote_url(instructions) == []


def test_secret_build_arg_flagged():
    instructions = [_inst("ARG", "API_TOKEN")]
    assert len(dc.check_secret_build_arg(instructions)) == 1


def test_non_secret_build_arg_ok():
    instructions = [_inst("ARG", "NODE_ENV=production")]
    assert dc.check_secret_build_arg(instructions) == []


def test_latest_base_image_flagged():
    instructions = [_inst("FROM", "node:latest")]
    assert len(dc.check_latest_base_image(instructions)) == 1


def test_pinned_base_image_ok():
    instructions = [_inst("FROM", "node:20.11-bookworm-slim")]
    assert dc.check_latest_base_image(instructions) == []


def test_scratch_base_image_ok():
    assert dc.check_latest_base_image([_inst("FROM", "scratch")]) == []


def test_pipe_curl_to_shell_flagged():
    instructions = [_inst("RUN", "curl -sSL https://get.example.com/install.sh | bash")]
    assert len(dc.check_pipe_to_shell(instructions)) == 1


def test_run_without_pipe_ok():
    instructions = [_inst("RUN", "npm install")]
    assert dc.check_pipe_to_shell(instructions) == []


def test_missing_healthcheck_flagged():
    instructions = [_inst("FROM", "node:20"), _inst("CMD", '["node", "app.js"]')]
    assert len(dc.check_missing_healthcheck(instructions)) == 1


def test_healthcheck_present_ok():
    instructions = [_inst("FROM", "node:20"), _inst("HEALTHCHECK", "CMD node healthcheck.js")]
    assert dc.check_missing_healthcheck(instructions) == []


def test_explicit_user_root_flagged():
    instructions = [_inst("FROM", "alpine:3.20"), _inst("USER", "root", 2)]
    findings = dc.check_missing_user(instructions)
    assert len(findings) == 1
    assert "явно запускается от root" in findings[0][1]


def test_explicit_uid_zero_flagged():
    instructions = [_inst("FROM", "alpine:3.20"), _inst("USER", "0:0", 2)]
    assert len(dc.check_missing_user(instructions)) == 1


def test_last_user_in_stage_wins():
    instructions = [
        _inst("FROM", "alpine:3.20"),
        _inst("USER", "root", 2),
        _inst("RUN", "apk add curl", 3),
        _inst("USER", "app", 4),
    ]
    assert dc.check_missing_user(instructions) == []


def test_user_inherited_from_local_parent_stage_ok():
    instructions = [
        _inst("FROM", "golang:1.23 AS builder"),
        _inst("USER", "app", 2),
        _inst("FROM", "builder", 3),
        _inst("CMD", '["/app"]', 4),
    ]
    assert dc.check_missing_user(instructions) == []


def test_stage_alias_is_not_an_unpinned_base_image():
    instructions = [
        _inst("FROM", "golang:1.23 AS builder"),
        _inst("FROM", "builder", 2),
    ]
    assert dc.check_latest_base_image(instructions) == []


def test_stage_alias_matched_case_insensitively():
    instructions = [
        _inst("FROM", "golang:1.23 AS Builder"),
        _inst("FROM", "BUILDER", 2),
    ]
    assert dc.check_latest_base_image(instructions) == []


def test_platform_flag_is_not_mistaken_for_image_name():
    instructions = [_inst("FROM", "--platform=linux/amd64 alpine:3.20")]
    assert dc.check_latest_base_image(instructions) == []


def test_unpinned_image_still_flagged_in_multistage():
    instructions = [
        _inst("FROM", "golang:1.23 AS builder"),
        _inst("FROM", "ubuntu", 2),
    ]
    findings = dc.check_latest_base_image(instructions)
    assert len(findings) == 1
    assert findings[0][0] == "stage 2: FROM ubuntu"


def test_arg_before_first_from_is_still_checked():
    instructions = [_inst("ARG", "API_TOKEN"), _inst("FROM", "alpine:3.20", 2)]
    findings = dc.check_secret_build_arg(instructions)
    assert len(findings) == 1
    assert findings[0][0] == "global: ARG API_TOKEN"


def test_dockerfile_location_carries_no_line_number():
    """Номер строки живёт в отдельном поле, иначе baseline протухает от сдвига файла."""
    early = dc.check_latest_base_image([_inst("FROM", "ubuntu", 1)])
    late = dc.check_latest_base_image([_inst("FROM", "ubuntu", 42)])
    assert early[0][0] == late[0][0]
    assert (early[0][2], late[0][2]) == (1, 42)
