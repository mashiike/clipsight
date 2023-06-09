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
      --permission-file=""       Permission file path ($CLIPSIGHT_PERMISSION_FILE)
      --sops-encrypted           Permission file is encrypted by sops ($CLIPSIGHT_SOPS_ENCRYPTED)

Commands:
  register --email=STRING --namespace="default" --iam-role-arn=STRING --region=STRING
    Register user

  grant --email=STRING --dashboard-id=STRING
    grant dashboard view auth to user

  revoke --email=STRING --dashboard-id=STRING
    revoke dashboard view auth from user

  serve
    Start a ClipSight server

  version
    Show version

Run "clipsight <command> --help" for more information on a command.
```

### DynamoDB Table mode

ClipSight uses DynamoDB to store user information and dashboard permissions.

if register user, execute `clipsight register` and `clipsight grant` command.
```
Usage: clipsight register --email=STRING --namespace="default" --iam-role-arn=STRING --region=STRING

Register user

Flags:
  -h, --help                        Show context-sensitive help.
      --log-level="info"            output log level ($CLIPSIGHT_LOG_LEVEL)
      --ddb-table="clipsight"       DynamoDB table name for user infomation ($CLIPSIGHT_DDB_TABLE)
      --permission-file=""          Permission file path ($CLIPSIGHT_PERMISSION_FILE)
      --sops-encrypted              Permission file is encrypted by sops ($CLIPSIGHT_SOPS_ENCRYPTED)

      --email=STRING                user email address
      --namespace="default"         quicksight namespace
      --iam-role-arn=STRING         IAM Role arn for quicksight user
      --region=STRING               quicksight user region ($AWS_DEFAULT_REGION)
      --register-quicksight-user    if quicksight user not exists, register this
      --expire-date=TIME            Expiration date for this user (RFC3399)
```

```
Usage: clipsight grant --email=STRING --dashboard-id=STRING

grant dashboard view auth to user

Flags:
  -h, --help                     Show context-sensitive help.
      --log-level="info"         output log level ($CLIPSIGHT_LOG_LEVEL)
      --ddb-table="clipsight"    DynamoDB table name for user infomation ($CLIPSIGHT_DDB_TABLE)
      --permission-file=""       Permission file path ($CLIPSIGHT_PERMISSION_FILE)
      --sops-encrypted           Permission file is encrypted by sops ($CLIPSIGHT_SOPS_ENCRYPTED)

      --email=STRING             user email address
      --dashboard-id=STRING      grant target dashboard id
      --expire-date=TIME         Expiration date for this user (RFC3399)
```


### Permission file mode

ClipSight users infomation and dashboard permissions are defined in a permission file.

permission file is YAML format.

```yaml
users:
  - email: "hoge@example.com"
    namespace: "default"
    iam_role_arn: "{{ must_env `QUICKSIGHT_IAM_ROLE_ARN` }}"
    region: "{{ must_env `AWS_DEFAULT_REGION` }}"
    dashboards:
      - id: "{{ must_env `QUICKSIGHT_DASHBOARD_ID` }}"
        expire_date: "2023-01-01T00:00:00Z"
    ttl: "2023-01-01T00:00:00Z"
```

if you want to encrypt permission file, use `sops` command.

```
$ sops permission.yaml
```

and use flag `--sops-encrypted` and `--permission-file` to ClipSight command.

permission file mode support only `serve` command.
when start ClipSight server, check quicksight user and grant dashboard permissions.


## LICENSE

MIT License

Copyright (c) 2023 IKEDA Masashi
