import pytest

from validator import ValidationError, validate_command

KEY = "ab" * 32
SSH = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl me@host"


def base(**kw):
    cmd = {"action": "e2ee_provision", "user_id": "alice", "ssh_public_key": SSH}
    cmd.update(kw)
    return cmd


def test_valid_commands_pass():
    validate_command(base())
    validate_command({"action": "e2ee_provision", "user_id": "alice"})
    validate_command({"action": "e2ee_set_key", "user_id": "alice", "ssh_public_key": SSH})
    validate_command({"action": "e2ee_delete", "user_id": "alice"})
    validate_command({"action": "e2ee_usage", "user_id": "alice", "quota_bytes": 10 * 2**30})


@pytest.mark.parametrize("action", ["mount", "umount", "create", "get_usage", "delete", "status"])
def test_removed_actions_are_rejected(action):
    with pytest.raises(ValidationError):
        validate_command({"action": action, "user_id": "alice"})


@pytest.mark.parametrize("user_id", ["bob\n", "ab", "a" * 33, "a-b-c", "../etc", "bob "])
def test_user_id_must_match_exactly(user_id):
    # "bob\n" passed when the pattern was used with match() and a trailing $
    with pytest.raises(ValidationError):
        validate_command(base(user_id=user_id))


@pytest.mark.parametrize("key", [
    SSH + "\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEvil evil",
    'command="rm -rf /" ' + SSH,
    "ssh-ed25519",
    "ssh-dss AAAAB3NzaC1kc3MAAACBAP",
    SSH + " " + "x" * 3000,
])
def test_ssh_key_must_be_single_clean_line(key):
    with pytest.raises(ValidationError):
        validate_command(base(ssh_public_key=key))


def test_set_key_requires_ssh_key():
    with pytest.raises(ValidationError):
        validate_command({"action": "e2ee_set_key", "user_id": "alice"})


def test_a_key_is_not_accepted_at_all():
    with pytest.raises(ValidationError):
        validate_command(base(master_key=KEY))


def test_unexpected_fields_rejected():
    with pytest.raises(ValidationError):
        validate_command({"action": "e2ee_delete", "user_id": "alice", "master_key": KEY})


@pytest.mark.parametrize("quota", [-1, "10", None, True, 1.5])
def test_usage_quota_must_be_int(quota):
    with pytest.raises(ValidationError):
        validate_command({"action": "e2ee_usage", "user_id": "alice", "quota_bytes": quota})
