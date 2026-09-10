import { IconLock, IconLogin } from "../ui/tabler";
import { Alert } from "../ui/Alert";
import { BrandMark } from "../ui/BrandMark";
import { Button } from "../ui/Button";
import { Field } from "../ui/Field";
import { ICON_SIZE, ICON_SIZE_SM, ICON_STROKE } from "../ui/icons";
import { noticeAlertTone } from "../labels";

export function SetupScreen(props: {
  password: string;
  repeat: string;
  busy: boolean;
  error: string;
  notice: string;
  onPassword: (value: string) => void;
  onRepeat: (value: string) => void;
  onSubmit: (ev: Event) => void;
  onGoLogin: () => void;
}) {
  return (
    <main class="auth-shell">
      <div class="auth-card card">
        <div class="auth-brand">
          <BrandMark />
          <h1>BlackTemple KN</h1>
        </div>
        <h2 class="auth-title">Первичная настройка</h2>
        <p class="lead">Защитите панель управления паролем.</p>
        <form class="auth-form" onSubmit={props.onSubmit}>
          <Field label="Пароль">
            <input
              type="password"
              name="password"
              autocomplete="new-password"
              value={props.password}
              onInput={(e) => props.onPassword((e.target as HTMLInputElement).value)}
            />
          </Field>
          <Field label="Повторите пароль">
            <input
              type="password"
              name="repeat"
              autocomplete="new-password"
              value={props.repeat}
              onInput={(e) => props.onRepeat((e.target as HTMLInputElement).value)}
            />
          </Field>
          {props.error ? <Alert tone="error">{props.error}</Alert> : null}
          {props.notice ? (
            <Alert tone={noticeAlertTone(props.notice)}>{props.notice}</Alert>
          ) : null}
          <Button type="submit" block disabled={props.busy} loading={props.busy}>
            Создать пароль
          </Button>
        </form>
        <p class="auth-aux">
          <Button variant="ghost" onClick={props.onGoLogin}>
            Войти
          </Button>
        </p>
      </div>
    </main>
  );
}

export function LoginScreen(props: {
  password: string;
  busy: boolean;
  error: string;
  notice: string;
  onPassword: (value: string) => void;
  onSubmit: (ev: Event) => void;
  onGoSetup: () => void;
}) {
  return (
    <main class="auth-shell">
      <div class="auth-card card">
        <div class="auth-brand">
          <span class="brand-mark" aria-hidden="true">
            <IconLock size={ICON_SIZE} stroke={ICON_STROKE} />
          </span>
          <h1>BlackTemple KN</h1>
        </div>
        <h2 class="auth-title">Вход</h2>
        <form class="auth-form" onSubmit={props.onSubmit}>
          <Field label="Пароль">
            <input
              type="password"
              name="password"
              autocomplete="current-password"
              value={props.password}
              onInput={(e) => props.onPassword((e.target as HTMLInputElement).value)}
            />
          </Field>
          {props.error ? <Alert tone="error">{props.error}</Alert> : null}
          {props.notice ? (
            <Alert tone={noticeAlertTone(props.notice)}>{props.notice}</Alert>
          ) : null}
          <Button
            type="submit"
            block
            disabled={props.busy}
            loading={props.busy}
            icon={<IconLogin size={ICON_SIZE_SM} stroke={ICON_STROKE} />}
          >
            Войти
          </Button>
        </form>
        <p class="auth-aux">
          <Button variant="ghost" onClick={props.onGoSetup}>
            Первый запуск
          </Button>
        </p>
      </div>
    </main>
  );
}
