# ADR-006: Minimal Preact UI embedded via go:embed

## Status

Accepted (R2 freeze)

## Context

APK — Flutter + Rive + custom fonts. На роутере это недопустимо по размеру и лицензиям.

## Decision

- Preact + TypeScript + Vite + plain CSS + inline SVG + system fonts.
- Запрещены React/Angular/Vue/Quasar/MUI/Bootstrap/Tailwind runtime/Rive/Lottie/custom font packs.
- Node.js только на build PC.
- Production: `go:embed` собранного `web/dist`.
- Gate: HTML+JS+CSS gzip **≤ 250 KB**.
- Bind LAN only. Главный экран — Connect/Disconnect, не Xray JSON.

## Consequences

Stream G может идти параллельно stream A после freeze OpenAPI.
