# Trace evidence

Агент обязан сохранять фактические следы:

- команда;
- exit code;
- релевантный stdout/stderr;
- путь артефакта;
- SHA256 если это бинарник/IPK.

Место для отчётов волны: `.ai/reports/` (можно коммитить sanitized reports).

Сырые дампы APK, токены, BlackKey — только `.research-local/`, никогда в git.

Формат имени:

```text
.ai/reports/<wave>-<task>-<yyyymmdd>.md
```
