export function App() {
  return (
    <main class="shell">
      <h1>BlackTemple KN</h1>
      <p class="status">
        <span class="dot" /> Отключено
      </p>
      <p class="meta">—</p>
      <button type="button" disabled>
        Подключить
      </button>
      <ul class="facts">
        <li>
          <span>Server</span>
          <span>Автоматически</span>
        </li>
        <li>
          <span>Routing</span>
          <span>Умный</span>
        </li>
        <li>
          <span>Key</span>
          <span>Нет</span>
        </li>
        <li>
          <span>Geodata</span>
          <span>Нет</span>
        </li>
      </ul>
    </main>
  );
}
