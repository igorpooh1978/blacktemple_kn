# Security Policy

## Reporting

Сообщайте уязвимости приватно через GitHub Security Advisories этого репозитория.

Не открывайте публичный issue с PoC, токенами, BlackKey или дампами конфигурации.

## Hard rules

- UI/API по умолчанию только LAN, не WAN.
- Первый запуск требует пароль администратора. Пароль хранится как hash, никогда plaintext.
- State-changing endpoints: POST, PUT, DELETE + CSRF + session.
- Rate limit на login.
- Secrets никогда полностью не возвращаются через UI/API/logs.
- Diagnostic bundle автоматически redaction: BlackKey, tokens, passwords, Authorization headers, sensitive query.
- Remote policy и support commands: schema allowlist. Нет shell, нет произвольного firewall, нет download+exec.
- Remote administrative commands по умолчанию **disabled**.
- `iptables -F` / `iptables -t nat -F` запрещены. Только chains с префиксом `BTKN_`.
- Kill switch только explicit advanced option. Default: FAIL OPEN.
- Pairing endpoint только LAN, one-time token, короткий TTL.

## Secrets in git

Не коммитить `.env`, router credentials, реальные BlackKey, APK, `.research-local/`.
