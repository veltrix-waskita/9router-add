# 9router-add

Modular automation system for adding accounts to providers integrated with 9router.

## Usage

```bash
node . add <provider> --email=x@y.com --password=xxx
node . list
node . inspect <provider> <id>
node . delete <provider> <id>
node . batch <batch-file.json>
```

## Setup

1. `npm install`
2. Copy `config.example.json` to `config.json` and edit
3. Run `node . add antigravity --email=... --password=...`
