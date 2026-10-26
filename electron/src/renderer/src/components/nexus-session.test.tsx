import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import '@/i18n';
import {
  __setNexusMeForTests,
  NexusSignInCard,
  NexusSignOutButton,
  takeNexusErrorFromUrl,
} from './nexus-session';

const apiFetch = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api/client', () => ({
  apiFetch,
  absoluteApiBase: () => 'https://voicestudio.example',
}));

afterEach(() => {
  act(() => __setNexusMeForTests(null));
  apiFetch.mockReset();
  window.history.replaceState(null, '', '/');
});

it('reads and strips the sign-in error left in the URL', () => {
  window.history.replaceState(null, '', '/?nexus_error=sem_acesso&tab=1#voices');
  expect(takeNexusErrorFromUrl()).toBe('sem_acesso');
  expect(window.location.search).toBe('?tab=1');
  expect(window.location.hash).toBe('#voices');
  expect(takeNexusErrorFromUrl()).toBeNull();
});

it('explains a missing VoiceStudio role', () => {
  render(<NexusSignInCard errorCode="sem_acesso" />);
  expect(screen.getByRole('alert').textContent).toMatch(/no access to VoiceStudio/);
});

it('falls back to a generic error for unknown codes', () => {
  render(<NexusSignInCard errorCode="something_new" />);
  expect(screen.getByRole('alert').textContent).toBe('Sign-in failed. Please try again.');
});

it('shows no error on a plain sign-in prompt and starts the sign-in', () => {
  const onSignIn = vi.fn();
  render(<NexusSignInCard errorCode={null} onSignIn={onSignIn} />);
  expect(screen.queryByRole('alert')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Sign in with Nexus' }));
  expect(onSignIn).toHaveBeenCalledOnce();
});

it('renders the sign-out button only with a Nexus session', async () => {
  const assign = vi.fn();
  vi.spyOn(window, 'location', 'get').mockReturnValue({
    ...window.location,
    assign,
  } as Location);
  const parar = vi.fn();
  window.NexusPonto = { iniciar: vi.fn(), parar };
  apiFetch.mockResolvedValue(new Response(null, { status: 204 }));

  const { container } = render(<NexusSignOutButton />);
  expect(container.innerHTML).toBe('');

  act(() =>
    __setNexusMeForTests({
      email: 'ana@example.com',
      name: 'Ana Lima',
      admin: false,
      system: 'voicestudio',
      ponto_script: 'https://nexus.example/v1/ponto/saida/lembrete.js',
    }),
  );
  const button = screen.getByRole('button', { name: 'Sign out (ana@example.com)' });
  await act(async () => {
    fireEvent.click(button);
  });
  expect(parar).toHaveBeenCalledOnce();
  expect(apiFetch).toHaveBeenCalledWith('/api/auth/nexus/logout', { method: 'POST' });
  expect(assign).toHaveBeenCalledWith('/');
  vi.restoreAllMocks();
  delete window.NexusPonto;
});
