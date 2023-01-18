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
      --ddb-table="clipsight"    DynamoDB table name for user infomation

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

## LICENSE

MIT License

Copyright (c) 2023 IKEDA Masashi
