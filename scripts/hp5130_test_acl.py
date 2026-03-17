#!/usr/bin/env python3
import os
import sys
import time
import paramiko


def main() -> int:
    host = os.environ["SWITCH_HOST"]
    user = os.getenv("SWITCH_USER", "admin")
    password = os.getenv("SWITCH_PASS", "")
    port = int(os.getenv("SWITCH_SSH_PORT", "22"))
    acl_num = os.getenv("SWITCH_TEST_ACL", "3100")
    key_path = os.getenv("SWITCH_KEY_PATH", "")

    if not password and not key_path:
        print("SWITCH_PASS or SWITCH_KEY_PATH not set", file=sys.stderr)
        return 2

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs = {
            "hostname": host,
            "port": port,
            "username": user,
            "allow_agent": False,
            "look_for_keys": False,
            "timeout": 10,
            "disabled_algorithms": {"pubkeys": ["rsa-sha2-512", "rsa-sha2-256"]}
        }

        if key_path:
            connect_kwargs["key_filename"] = key_path
        else:
            connect_kwargs["password"] = password

        client.connect(**connect_kwargs)
        chan = client.invoke_shell()

        commands = [
            "display acl {}".format(acl_num)
        ]

        output = ""
        for cmd in commands:
            chan.send(cmd + "\n")
            time.sleep(1)
            if chan.recv_ready():
                output += chan.recv(65535).decode("utf-8", errors="ignore")

        chan.close()
        client.close()

        print(output)
        return 0
    except Exception as exc:
        print(f"SSH FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
