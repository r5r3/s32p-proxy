#!/bin/bash
#
../../versity-patched/versitygw --debug --iam-vault-endpoint-url http://127.0.0.1:8200 --iam-vault-root-token root --iam-vault-secret-storage-path versitygw --iam-vault-mount-path secret --access test --secret test posix /tmp/gw
