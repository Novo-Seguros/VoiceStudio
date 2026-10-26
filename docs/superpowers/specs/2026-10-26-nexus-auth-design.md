# Login Nexus no VoiceStudio (fork Novo Seguros)

**Status:** design aprovado (2026-10-26)
**Escopo:** só o fork `Novo-Seguros/VoiceStudio`, deploy web em `https://voicestudio.novoapp.dev`.

## Contexto

O Nexus é o broker de identidade e autorização da Novo Seguros. O sistema `voicestudio`
já está cadastrado nele:

- modo `GRANULAR`, `papelUnico = true`, sem escopo de empresa;
- URL / `aud` / origin: `https://voicestudio.novoapp.dev`;
- redirect URI: `https://voicestudio.novoapp.dev/auth/callback`;
- OAuth client: `fc28487a-321c-4467-a711-f188076cfdf3`;
- permissões `usar` e `admin`; papéis `usuario` (`usar`), `administrador` (`usar|admin`)
  e o `admin` automático do Nexus (`usar|admin`, também gere usuários no Nexus).

Hoje o VoiceStudio autentica acessos remotos por chave mestra (`OMNIVOICE_API_KEY`,
trocada por sessão `ov_session`), PIN de compartilhamento ou CIDR confiável. Não há
usuários nem permissão por pessoa: só os níveis `consume` e `admin`
(`backend/core/auth.py`). Loopback sempre recebe acesso total.

## Objetivo

Com o modo Nexus ligado, quem abre o VoiceStudio pelo navegador entra pelo Nexus, e o
nível de acesso vem do papel da pessoa no Nexus. Sem as variáveis do Nexus, nada muda
(desktop, Docker e build de código-fonte idênticos ao upstream).

## Decisões

1. **BFF no FastAPI.** O backend conduz o OAuth PKCE e guarda os tokens do Nexus em
   memória. O navegador só recebe o cookie `ov_session` (HttpOnly, SameSite=Strict,
   Secure sob HTTPS) que o VoiceStudio já usa.
2. **Ativação por ambiente.** `NEXUS_CLIENT_ID` liga o modo. Exige também
   `NEXUS_SUPABASE_URL`, `NEXUS_SUPABASE_ANON_KEY`, `NEXUS_API_URL` (base sem `/v1`) e
   `NEXUS_APP_URL` (sem barra final). `NEXUS_SYSTEM_SLUG` é opcional (padrão
   `voicestudio`). Configuração incompleta com `NEXUS_CLIENT_ID` definido = falha
   fechada: o modo fica ligado, o login responde erro de configuração e nenhum acesso
   remoto sem credencial passa.
3. **Mapeamento de permissões** (`app_metadata.permissions`, pipe-string; se vier
   objeto por sistema, usa a chave do slug):
   - `usar` → `{consume}`
   - `admin` → `{consume, admin}` (com ou sem `usar`)
   - nenhuma das duas → login recusado (`sem_acesso`), sem sessão.
4. **Sessão Nexus** em store próprio, em memória e por processo, no mesmo molde do
   `AdminSessionStore`: token opaco `ovs_nexus_session_<43 chars>`, hash HMAC com
   pepper do processo, limite de 256 sessões, duração máxima de 8 h. Guarda `sub`,
   e-mail, nome, níveis de acesso, access token, refresh token e expiração do access
   token. Reiniciar o processo derruba as sessões; o novo login é silencioso enquanto a
   sessão SSO do Nexus existir.
5. **Renovação preguiçosa no servidor.** Um middleware ASGI (fora do
   `BearerKeyMiddleware`) vê o cookie de sessão Nexus e, se o access token vence em
   menos de 60 s, renova com `grant_type=refresh_token`, guarda o refresh rotacionado e
   recalcula os níveis a partir do token novo. Um lock por sessão evita duas renovações
   simultâneas. Falha definitiva (400/401 do Nexus, token inválido, sem `usar`) revoga a
   sessão; falha transitória (rede, 5xx) mantém a sessão até a expiração do access token
   + 5 min de tolerância.
6. **Nova identidade `PrincipalKind.NEXUS_SESSION`.** Entra pelo mesmo cookie
   `ov_session` (o prefixo do token decide o store). Ajustes:
   - checagens de admin (`_request_presents_admin_credential`, `ws_remote_authorized`)
     aceitam a sessão Nexus quando ela tem o nível exigido (`admin` para admin,
     `consume` para WebSocket de consumo);
   - `BearerKeyMiddleware` fica ativo com chave de API **ou** modo Nexus e aceita
     `NEXUS_SESSION`;
   - `_admin_credential_configured` é verdadeiro com o modo Nexus ligado (GETs de admin
     deixam de ficar abertos no modo servidor);
   - recusa sem credencial no modo Nexus responde `401 {"detail": "Nexus login
     required"}`; sessão Nexus sem `admin` em rota de admin responde
     `403 {"detail": "Nexus admin permission required"}` (sem "api key", para a UI não
     voltar à tela de login);
   - `OMNIVOICE_API_KEY` continua valendo (acesso de emergência, scripts, MCP).
7. **Proxy.** O uvicorn 0.52 já reescreve o cliente pelo `X-Forwarded-For` quando o par
   é 127.0.0.1. Defesa extra no modo Nexus: requisição de par loopback com
   `CF-Connecting-IP`, `X-Forwarded-For`, `X-Real-IP` ou `Forwarded` nunca vira
   `LOOPBACK` nem passa nos gates de loopback; um middleware reescreve o `client` do
   escopo para um endereço não-loopback (`0.0.0.0`) antes de qualquer gate.
8. **Rotas novas** (todas públicas para os gates, cada uma valida o que precisa):
   - `GET /auth/login` — gera `state` e `code_verifier`, guarda o verifier no servidor
     (10 min, limite de 512) ligado ao `state`, grava o cookie `ov_nexus_state`
     (HttpOnly, SameSite=Lax, 10 min) e redireciona para
     `{NEXUS_SUPABASE_URL}/auth/v1/oauth/authorize` com `response_type=code`,
     `client_id`, `redirect_uri={NEXUS_APP_URL}/auth/callback`, `code_challenge`
     (S256), `state` e `scope=openid email profile`.
   - `GET /auth/callback` — confere `state` contra o cookie e o store (uso único),
     troca o código em `{NEXUS_SUPABASE_URL}/auth/v1/oauth/token` (header `apikey`),
     valida o JWT, mapeia os níveis, cria a sessão, grava `ov_session`, apaga
     `ov_nexus_state` e redireciona para `/`. Qualquer erro redireciona para
     `/?nexus_error=<codigo>` (`estado_invalido`, `troca_falhou`, `token_invalido`,
     `sem_acesso`, `nexus_indisponivel`, `configuracao`, `cancelado`), sem detalhes
     sensíveis.
   - `GET /api/auth/nexus/me` — `404` com o modo desligado; `401` sem sessão; senão
     `{email, name, admin, system, ponto_script}`.
   - `POST /api/auth/nexus/logout` — revoga a sessão local, chama
     `POST {NEXUS_API_URL}/v1/auth/logout` com o refresh token (best-effort, 5 s),
     apaga o cookie; exige o header CSRF do VoiceStudio.
   - `POST /api/nexus-ponto/{acao}` — `acao ∈ {situacao, registrar, dispensar}` (outra
     → 404); exige sessão Nexus (senão 401) e o header CSRF; renova o token se preciso
     (mesma rotina do item 5); repassa o corpo JSON sem mudar para
     `{NEXUS_API_URL}/v1/ponto/saida/<acao>` com `Authorization: Bearer`, o
     `User-Agent` do navegador e timeout de 10 s; devolve status e JSON do Nexus; erro →
     `502 {}`. Nunca loga corpo nem token.
9. **Validação do JWT.** `PyJWT` + `PyJWKClient` em `{NEXUS_API_URL}/v1/auth/jwks`
   (cache de 10 min), algoritmo `ES256` (aceita `RS256` se a chave publicada for RSA),
   `iss = {NEXUS_SUPABASE_URL}/auth/v1`, `aud = NEXUS_APP_URL`, `exp` obrigatório,
   `app_metadata.system_slug = NEXUS_SYSTEM_SLUG`.
10. **CSP.** Com o modo Nexus ligado, o backend acrescenta a origem de `NEXUS_API_URL`
    ao `script-src` do `index.html` servido, pelo mesmo caminho do `spa_inject` que já
    injeta a base da API. O lembrete usa o modo B, então `connect-src` não muda.
11. **UI.** O `WebAuthGate` ganha o modo `nexus`: cartão com o botão "Entrar com
    Nexus" (navega para `/auth/login`) e a mensagem do `nexus_error` da URL. O cliente
    de API reconhece `Nexus login required` como modo `nexus`. Um componente
    `NexusSession` (montado só na build web) consulta `/api/auth/nexus/me`; com sessão,
    carrega `lembrete.js` e chama
    `NexusPonto.iniciar({ endpoint: '/api/nexus-ponto', sistema, cabecalhos })` com o
    header CSRF, e mostra a pessoa logada com a opção "Sair", que chama
    `NexusPonto.parar()`, o logout e recarrega a página.
12. **Fora do escopo:** espelho de usuários e backfill (§3.3/§3.9 do guia do Nexus —
    não há tabela de usuários), escopo de empresa, esconder telas de admin para quem
    não é admin (o backend já recusa com 403; fica para uma melhoria seguinte).

## Testes

- `tests/test_nexus_auth.py` (pytest): validação do JWT com JWKS falso (assinatura,
  `iss`, `aud`, `exp`, `system_slug`), mapeamento de permissões, login completo com
  Nexus simulado, `state` inválido/reutilizado, renovação com rotação e revogação,
  defesa de proxy, ponto (ações válidas, 404, 401, 502), logout, e modo desligado
  idêntico ao atual.
- Vitest do `WebAuthGate` no modo `nexus`.
- Textos novos nas 21 locales (`tests/test_locale_parity.py`, `locale:check`).

## Docs

Seção "Nexus login (Novo Seguros fork)" em `docs/api-auth.md` com as variáveis, o
mapeamento, o comportamento atrás de proxy e o lembrete do ponto.
