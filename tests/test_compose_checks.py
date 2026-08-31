from fstec_lint.checks import compose_checks as cc


def test_root_user_flagged_when_missing():
    compose = {"services": {"web": {"image": "nginx:1.27"}}}
    findings = cc.check_root_user(compose)
    assert len(findings) == 1
    assert findings[0][0] == "service:web"


def test_root_user_ok_when_user_set():
    compose = {"services": {"web": {"image": "nginx:1.27", "user": "1000:1000"}}}
    assert cc.check_root_user(compose) == []


def test_privileged_flagged():
    compose = {"services": {"web": {"privileged": True}}}
    assert len(cc.check_privileged(compose)) == 1


def test_dangerous_capabilities_flagged():
    compose = {"services": {"web": {"cap_add": ["SYS_ADMIN", "CHOWN"]}}}
    findings = cc.check_dangerous_capabilities(compose)
    assert len(findings) == 1
    assert "SYS_ADMIN" in findings[0][1]


def test_secret_in_environment_dict_flagged():
    compose = {"services": {"db": {"environment": {"POSTGRES_PASSWORD": "hunter2"}}}}
    findings = cc.check_secrets_in_environment(compose)
    assert len(findings) == 1


def test_secret_file_variant_not_flagged():
    compose = {
        "services": {"db": {"environment": {"POSTGRES_PASSWORD_FILE": "/run/secrets/db_password"}}}
    }
    assert cc.check_secrets_in_environment(compose) == []


def test_secret_env_variable_reference_not_flagged():
    compose = {"services": {"db": {"environment": {"POSTGRES_PASSWORD": "${DB_PASSWORD}"}}}}
    assert cc.check_secrets_in_environment(compose) == []


def test_secret_in_environment_list_form_flagged():
    compose = {"services": {"db": {"environment": ["DB_PASSWORD=hunter2"]}}}
    assert len(cc.check_secrets_in_environment(compose)) == 1


def test_exposed_sensitive_port_short_syntax_flagged():
    compose = {"services": {"db": {"ports": ["5432:5432"]}}}
    findings = cc.check_exposed_sensitive_ports(compose)
    assert len(findings) == 1


def test_exposed_sensitive_port_bound_to_loopback_ok():
    compose = {"services": {"db": {"ports": ["127.0.0.1:5432:5432"]}}}
    assert cc.check_exposed_sensitive_ports(compose) == []


def test_non_sensitive_port_not_flagged():
    compose = {"services": {"web": {"ports": ["8080:8080"]}}}
    assert cc.check_exposed_sensitive_ports(compose) == []


def test_latest_tag_flagged():
    compose = {"services": {"web": {"image": "myorg/web:latest"}}}
    assert len(cc.check_latest_tag(compose)) == 1


def test_pinned_tag_ok():
    compose = {"services": {"web": {"image": "myorg/web:1.4.2"}}}
    assert cc.check_latest_tag(compose) == []


def test_digest_pinned_ok():
    compose = {"services": {"web": {"image": "myorg/web:1.4.2@sha256:" + "a" * 64}}}
    assert cc.check_latest_tag(compose) == []


def test_host_network_flagged():
    compose = {"services": {"web": {"network_mode": "host"}}}
    assert len(cc.check_host_network(compose)) == 1


def test_docker_socket_mount_flagged():
    compose = {"services": {"web": {"volumes": ["/var/run/docker.sock:/var/run/docker.sock"]}}}
    assert len(cc.check_docker_socket_mount(compose)) == 1


def test_read_only_missing_flagged():
    compose = {"services": {"web": {}}}
    assert len(cc.check_no_read_only(compose)) == 1


def test_read_only_true_ok():
    compose = {"services": {"web": {"read_only": True}}}
    assert cc.check_no_read_only(compose) == []


def test_no_new_privileges_missing_flagged():
    compose = {"services": {"web": {}}}
    assert len(cc.check_missing_no_new_privileges(compose)) == 1


def test_no_new_privileges_present_ok():
    compose = {"services": {"web": {"security_opt": ["no-new-privileges:true"]}}}
    assert cc.check_missing_no_new_privileges(compose) == []


def test_docker_api_exposed_flagged():
    compose = {"services": {"web": {"ports": ["2375:2375"]}}}
    assert len(cc.check_docker_api_exposed(compose)) == 1


def test_docker_api_bound_to_loopback_ok():
    compose = {"services": {"web": {"ports": ["127.0.0.1:2375:2375"]}}}
    assert cc.check_docker_api_exposed(compose) == []


def test_missing_resource_limits_flagged():
    compose = {"services": {"web": {}}}
    assert len(cc.check_missing_resource_limits(compose)) == 1


def test_resource_limits_via_legacy_keys_ok():
    compose = {"services": {"web": {"mem_limit": "512m"}}}
    assert cc.check_missing_resource_limits(compose) == []


def test_resource_limits_via_deploy_ok():
    compose = {"services": {"web": {"deploy": {"resources": {"limits": {"memory": "512M"}}}}}}
    assert cc.check_missing_resource_limits(compose) == []


def test_missing_healthcheck_flagged():
    compose = {"services": {"web": {}}}
    assert len(cc.check_missing_healthcheck(compose)) == 1


def test_healthcheck_present_ok():
    compose = {"services": {"web": {"healthcheck": {"test": ["CMD", "true"]}}}}
    assert cc.check_missing_healthcheck(compose) == []


def test_healthcheck_disabled_flagged():
    compose = {"services": {"web": {"healthcheck": {"disable": True}}}}
    assert len(cc.check_missing_healthcheck(compose)) == 1


def test_debug_mode_enabled_flagged():
    compose = {"services": {"web": {"environment": {"DEBUG": "true"}}}}
    assert len(cc.check_debug_mode_enabled(compose)) == 1


def test_debug_mode_disabled_ok():
    compose = {"services": {"web": {"environment": {"DEBUG": "false"}}}}
    assert cc.check_debug_mode_enabled(compose) == []


def test_sensitive_host_mount_flagged():
    compose = {"services": {"web": {"volumes": ["/etc:/host-etc"]}}}
    assert len(cc.check_sensitive_host_mount(compose)) == 1


def test_regular_volume_mount_ok():
    compose = {"services": {"web": {"volumes": ["./data:/app/data"]}}}
    assert cc.check_sensitive_host_mount(compose) == []
