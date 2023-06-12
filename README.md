# ClipSight　
![Latest GitHub release](https://img.shields.io/github/release/mashiike/clipsight.svg)
![Github Actions test](https://github.com/mashiike/clipsight/workflows/Test/badge.svg?branch=main)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/mashiike/clipsight/blob/master/LICENSE)

ClipSight provides an embedded site for sharing several Amazon QuickSight dashboards externally.

## Install

### Binary packages

[Releases](https://github.com/mashiike/clipsight/releases)


## Usage 

```
Usage: clipsight <command>

Flags:
  -h, --help                     Show context-sensitive help.
      --log-level="info"         output log level ($CLIPSIGHT_LOG_LEVEL)
      --ddb-table="clipsight"    DynamoDB table name for user infomation ($CLIPSIGHT_DDB_TABLE)

Commands:
  register --email=STRING --namespace="default" --iam-role-arn=STRING --region=STRING
    Register user

  grant --email=STRING --dashboard-id=STRING
    grant dashboard view auth to user

  revoke --email=STRING --dashboard-id=STRING
    revoke dashboard view auth from user

  serve
    Start a ClipSight server

  plan --config-path="."
    Plan of sync config and DynamoDB

  apply --config-path="."
    Apply sync config and DynamoDB

  version
    Show version

Run "clipsight <command> --help" for more information on a command.
```

## Permission management as a code

ClipSight provides a command to manage user permissions as a code.

for example, can manage user permissions with a yaml file like this.

```yaml
required_version: ">=0.0.0"

users:
  - email: "tora@example.com"
    namespace: "external"
    iam_role_arn: "{{ must_env `IAM_ROLE_ARN` }}"
    region: "{{ must_env `AWS_REGION` }}"
    dashboards:
      - dashboard_id: 12345678-1234-1234-1234-123456789012
        expire: "2021-01-01T00:00:00Z"
    enabled: true
  - email: "piyo@example.com"
    iam_role_arn: "{{ must_env `IAM_ROLE_ARN` }}"
    dashboards:
      - dashboard_id: 12345678-1234-1234-1234-123456789012
        expire: "2021-01-01T00:00:00Z"
      - dashboard_id: 00000000-0000-0000-0000-000000000000
    enabled: true
```

yaml files can be split. read all files with `--config-path` option.

modify plan and apply with `clipsight plan` and `clipsight apply` command.
```bash
$ clipsight plan --config-path /path/to/config
```

```bash
$ clipsight apply --config-path /path/to/config
```

## LICENSE

MIT License

Copyright (c) 2023 IKEDA Masashi
