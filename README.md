# BB AGY Usage

Shows local AGY (Antigravity) 5-hour and weekly quota windows in BB's Provider Usage panel.

## Requirements

- BB 0.43 or newer.
- A local AGY CLI (`agy`) login on the host.

## Credential lookup and fallback order

The plugin checks local credential sources automatically in this order:

1. Custom token file path from `AGY_TOKEN_PATH` or `ANTIGRAVITY_TOKEN_PATH`.
2. `~/.gemini/antigravity-cli/antigravity-oauth-token`.
3. `~/.gemini/antigravity/antigravity-oauth-token`.
4. OS keyring (`service="gemini"`, `account="antigravity"`):
   - **macOS**: Keychain via `security find-generic-password` (supports both `go-keyring-base64:` and plain JSON payloads).
   - **Windows**: Windows Credential Manager (`gemini:antigravity`).
   - **Linux**: Secret Service via `secret-tool`.

## Privacy and credentials

The plugin reads the local login token only to request quota data. It does not log, display, or persist access or refresh tokens. When the access token is expired, it runs `agy models` to let the local CLI refresh the token without starting an inference turn.

## Install

```sh
bb plugin install git:https://github.com/sbrin/bb-agy-usage.git
```
