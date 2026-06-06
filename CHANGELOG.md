# Changelog

## v9.0.0

First release on the `/v9` module path. This is a **breaking** release: the import path
changed and three exported signatures changed. Most of the functional work targets
Active Directory interoperability (password change/reset, account salt lookup, realm name
canonicalization, and keytab handling) in service of go-smb and kerbtool.

### Upgrading from v8

1. Update imports: `github.com/jfjallid/gokrb5/v8/...` → `github.com/jfjallid/gokrb5/v9/...`.
2. Update the call sites for the three changed signatures listed under **Breaking** below.
3. `go get github.com/jfjallid/gokrb5/v9@v9.0.0`.

### Breaking

- **Module import path is now `github.com/jfjallid/gokrb5/v9`.** v8 and v9 are distinct
  modules to the Go toolchain; all imports must be updated.
- `messages.(*ASRep).Verify` gained a `aliases *config.RealmAliases` parameter:
  `Verify(cfg, aliases, creds, asReq)`. Pass `nil` for the previous behaviour.
- `messages.(*TGSRep).Verify` gained a `aliases *config.RealmAliases` parameter:
  `Verify(cfg, aliases, tgsReq)`. Pass `nil` for the previous behaviour.
- `kadmin.ChangePasswdMsg` now separates the authenticated client from the target account.
  Old: `ChangePasswdMsg(cname, realm, password, tkt, sessionKey)`.
  New: `ChangePasswdMsg(authCName, authRealm, targName, targRealm, password, tkt, sessionKey)`.
  For a self-service change pass an empty `targName`/`targRealm`.

### Added

- `client.(*Client).SetPasswd(targetUser, targetRealm, newPasswd)` — administratively reset
  another principal's password using the caller's TGT to obtain a `kadmin/changepw` service
  ticket and naming the target in the request (caller must hold reset rights).
- `client.(*Client).RequestSalt(cname, realm)` — query a KDC for an account's salt via a
  pre-authentication-less AS-REQ, reading `PA-ETYPE-INFO2` (falling back to `PA-ETYPE-INFO`).
  Needed to derive password-based keys for accounts whose salt is not the default form.
- `keytab.(*Keytab).Principal()` — returns the principal name and realm of the keytab's first
  entry, for deriving a login identity from a single-principal keytab.
- `NewWithKeytab` now derives the login principal from the keytab when `username` and/or
  `realm` are empty; non-empty arguments still override (e.g. to pin a realm). Multi-component
  principals (e.g. `host/...`) are preserved.
- `config.RealmsEquivalent(aliases, a, b)` — alias-aware realm comparison; the alias-aware
  form of `EqualRealm`, used by KDC-reply verification.

### Changed (behaviour)

- **RFC 6806 realm canonicalization.** The client now learns a realm alias from the AS-REP
  (including the PKINIT path) when the KDC returns the client realm in a different form than
  requested (commonly NetBIOS short name → DNS form). AS-REP/TGS-REP realm verification is now
  alias-aware, so a KDC-asserted equivalence is accepted while unrelated realms are still
  rejected.
- **Keytab login etype selection.** `Login()` now constrains the AS-REQ requested etypes to
  those the keytab actually holds a key for (preserving configured preference order). Offering
  an etype that cannot be keyed (e.g. AES256 when the keytab only holds AES128) previously
  broke pre-authentication and/or AS-REP decryption.
- **Keytab kvno tolerance.** `keytab.GetEncryptionKey` now retries ignoring the kvno when no
  exact kvno match is found, matching MIT/Heimdal behaviour. This tolerates hand-built keytabs
  carrying a stale kvno label.
- **Self-service password change.** `ChangePasswd` now omits the target name/realm so the KDC
  treats the request as a self-service *change* (authorized by the initial ticket) rather than
  an administrative *set/reset* (which an account cannot perform on itself and which returned
  ACCESSDENIED). The authenticator uses the realm the KDC placed in the ticket.
- **kpasswd server resolution.** `config.GetKpasswdServers` now consults `krb5.conf` first
  (including a NetBIOS/DNS alias fallback and deriving the KDC host on port 464 when no
  `kpasswd_server`/`admin_server` is configured), using DNS SRV only as a last resort. This
  keeps password changes on the configured / ticket-issuing DC.
  > Note: setups (typically MIT/Heimdal) where the kpasswd/admin host differs from the KDC and
  > relied on `_kpasswd._tcp` SRV records will now be directed at the KDC host on port 464.

### Fixed / hardening

- `kadmin.(*Reply).Unmarshal` hardened: detects a bare `KRB-ERROR` reply (APPLICATION 30) that
  some servers return when the AP-REQ itself is rejected, bounds-checks the length fields
  (minimum length, clamps `MessageLength`, validates `APREPLength`), and surfaces KRB-ERROR
  unmarshal failures instead of silently ignoring them.
- `kadmin.(*Reply).Decrypt` now rejects a decrypted result buffer shorter than the 2-byte
  result code, so a malformed reply can no longer be misread as `KRB5_KPASSWD_SUCCESS`.
- `config.(*RealmAliases).Resolve` is now nil-safe (a nil receiver behaves as an empty table),
  so callers holding an optional alias table need not nil-check.

### Docs

- README rewritten: states the fork's purpose (Active-Directory-focused, not strict RFC
  conformance; changed as needed for go-smb and kerbtool), removes dead badges and links
  (upstream version table, non-existent CI-workflow and USAGE.md links), and corrects the Go
  version requirement to 1.24.
