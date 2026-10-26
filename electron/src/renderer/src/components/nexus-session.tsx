/**
 * Nexus sign-in (Novo Seguros fork) for the web deployment.
 *
 * The backend runs the whole OAuth flow and keeps the Nexus tokens; the page
 * only learns who is signed in (`/api/auth/nexus/me`), loads the Nexus
 * clock-out reminder in its token-less mode (calls go through
 * `/api/nexus-ponto/*` on this origin) and offers a sign-out button.
 */
import { useEffect, useSyncExternalStore } from 'react';
import { useTranslation } from 'react-i18next';
import { KeyRoundIcon, LogOutIcon } from 'lucide-react';
import { CSRF_HEADER_NAME } from '@shared/api/authSession';
import { absoluteApiBase, apiFetch } from '@/lib/api/client';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

export type NexusMe = {
  email: string;
  name: string;
  admin: boolean;
  system: string;
  ponto_script: string;
};

type NexusPonto = {
  iniciar(options: {
    endpoint: string;
    sistema: string;
    cabecalhos?: () => Record<string, string>;
  }): void;
  parar(): void;
};

declare global {
  interface Window {
    NexusPonto?: NexusPonto;
  }
}

export const NEXUS_LOGIN_PATH = '/auth/login';
const NEXUS_ERROR_PARAM = 'nexus_error';
const PONTO_SCRIPT_ID = 'nexus-ponto-lembrete';

let current: NexusMe | null = null;
const listeners = new Set<() => void>();

function setNexusMe(next: NexusMe | null) {
  current = next;
  listeners.forEach((listener) => listener());
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function useNexusMe(): NexusMe | null {
  return useSyncExternalStore(
    subscribe,
    () => current,
    () => null,
  );
}

/** Reads and removes `?nexus_error=` left by a failed sign-in callback. */
export function takeNexusErrorFromUrl(win: Window = window): string | null {
  const url = new URL(win.location.href);
  const code = url.searchParams.get(NEXUS_ERROR_PARAM);
  if (code === null) return null;
  url.searchParams.delete(NEXUS_ERROR_PARAM);
  win.history.replaceState(win.history.state, '', url.toString());
  return code;
}

function useNexusErrorText(code: string | null): string | null {
  const { t } = useTranslation();
  switch (code) {
    case null:
    case '':
      return null;
    case 'estado_invalido':
      return t('nexus.error_estado_invalido');
    case 'troca_falhou':
      return t('nexus.error_troca_falhou');
    case 'token_invalido':
      return t('nexus.error_token_invalido');
    case 'sem_acesso':
      return t('nexus.error_sem_acesso');
    case 'nexus_indisponivel':
      return t('nexus.error_nexus_indisponivel');
    case 'configuracao':
      return t('nexus.error_configuracao');
    case 'cancelado':
      return t('nexus.error_cancelado');
    default:
      return t('nexus.error_generic');
  }
}

export function NexusSignInCard({
  errorCode,
  onSignIn = () => window.location.assign(NEXUS_LOGIN_PATH),
}: {
  errorCode: string | null;
  onSignIn?: () => void;
}) {
  const { t } = useTranslation();
  const error = useNexusErrorText(errorCode);
  return (
    <div
      className="flex h-full min-h-screen items-center justify-center bg-background p-6"
      role="dialog"
      aria-modal="true"
    >
      <Card className="w-full max-w-md">
        <CardHeader>
          <div className="mb-2 flex size-9 items-center justify-center rounded-md bg-primary/10 text-primary">
            <KeyRoundIcon className="size-5" />
          </div>
          <CardTitle>{t('nexus.sign_in_title')}</CardTitle>
          <CardDescription>{t('nexus.sign_in_hint')}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {error && (
            <p className="text-xs text-destructive" role="alert">
              {error}
            </p>
          )}
          <Button className="w-full" type="button" onClick={onSignIn}>
            {t('nexus.sign_in')}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

function startPontoReminder(me: NexusMe) {
  const begin = () =>
    window.NexusPonto?.iniciar({
      endpoint: `${absoluteApiBase()}/api/nexus-ponto`,
      sistema: me.system,
      cabecalhos: () => ({ [CSRF_HEADER_NAME]: '1' }),
    });
  if (document.getElementById(PONTO_SCRIPT_ID)) {
    begin();
    return;
  }
  const script = document.createElement('script');
  script.id = PONTO_SCRIPT_ID;
  script.src = me.ponto_script;
  script.async = true;
  // The reminder never blocks the app: a failed load just shows nothing.
  script.onload = begin;
  document.head.appendChild(script);
}

/** Loads the signed-in Nexus user once; inert when Nexus sign-in is off (404). */
export function NexusSessionSync() {
  useEffect(() => {
    let cancelled = false;
    void apiFetch('/api/auth/nexus/me')
      .then((response) => response.json() as Promise<NexusMe>)
      .then((me) => {
        if (cancelled) return;
        setNexusMe(me);
        startPontoReminder(me);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, []);
  return null;
}

export async function signOutOfNexus() {
  window.NexusPonto?.parar();
  try {
    await apiFetch('/api/auth/nexus/logout', { method: 'POST' });
  } finally {
    setNexusMe(null);
    window.location.assign('/');
  }
}

export function NexusSignOutButton({ compact = false }: { compact?: boolean }) {
  const { t } = useTranslation();
  const me = useNexusMe();
  if (!me) return null;
  const label = t('nexus.sign_out', { email: me.email });
  return (
    <Button
      type="button"
      variant="ghost"
      size={compact ? 'icon-xs' : 'icon-sm'}
      aria-label={label}
      title={label}
      className={cn('workspace-nav-item')}
      onClick={() => void signOutOfNexus()}
    >
      <LogOutIcon className="workspace-nav-icon" />
    </Button>
  );
}

/** Test seam. */
export function __setNexusMeForTests(me: NexusMe | null) {
  setNexusMe(me);
}
