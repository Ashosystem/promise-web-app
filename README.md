# Promise Voucher Network

A vanilla-JS single-page app (Firebase v8 Auth + Firestore, TweetNaCl end-to-end
encryption) for sending, transferring and redeeming promise vouchers. All app
logic lives in `www/app.js`; `www/` is wrapped by Capacitor for Android and is
published verbatim to GitHub Pages at
<https://ashosystem.github.io/promise-web-app/> by
`.github/workflows/deploy-pages.yml` on every push to `master` that touches
`www/**`.

## Send-to-anyone: manual Firebase console steps

The send-to-anyone feature (sending a voucher to an email address or phone
number that has no account yet) is implemented entirely client-side, but it
cannot work until the following one-time changes are made **by hand in the
Firebase console** (project `promise-network-mvp`). Security rules are managed
in the console, not in this repo. Until these are applied, the code degrades
safely: provisioning fails with a clear error toast and nothing is sent.

### 1. Firestore security rules

Update the rules so that:

- **`users/{uid}`** — allow `create` when `request.auth.uid == uid`.
  Account provisioning signs in briefly *as the new account* (via a secondary
  Firebase app) and writes its own user doc, so the create is authored by the
  new uid — this is exactly what an owner-only create rule permits. Keep
  authenticated reads: recipient lookups (`where('email', ...)`,
  `where('phoneNumber', ...)`) depend on them.
- **`pending-users/{phone}`** (doc id is the E.164 number, e.g.
  `+447700900000` — the `+` is a legal doc id character) — allow authenticated
  `create` and `read`. Allow `delete` by the claimer
  (`request.auth.token.phone_number == resource.data.phone`); allowing
  authenticated delete generally is also acceptable at this trust level.
- **`promises`** — phone-addressed promises have `receiverId: null` and route
  on `receiverPhone`, so a phone-auth user must be able to read and update
  promises where `request.auth.token.phone_number == resource.data.receiverPhone`
  (the claim sweep updates `receiverId`, `receiverEmail` and
  `contentEncryptedForReceiver`).

### 2. Authentication settings

- Check whether **Email enumeration protection** is enabled
  (Authentication → Settings). It changes how `auth/email-already-in-use`
  is reported during provisioning; the app surfaces the raw error message
  either way, but it's worth knowing which behaviour you'll see.
- Customise the **password-reset email template**
  (Authentication → Templates). This email doubles as the invitation for
  provisioned accounts, so reword it along the lines of: *"You've been
  invited to Promise Voucher Network — set your password to view your
  voucher."*

### 3. Hosted app URL

Phone claim links use `location.origin` on the web, and fall back to the
hardcoded constant in `getAppUrl()` (`www/app.js`) when running inside the
Capacitor wrapper. That constant is
`https://ashosystem.github.io/promise-web-app/` — verified live and serving
the app. If the hosting ever moves (custom domain, Firebase Hosting), update
`getAppUrl()`.

### 4. Follow-up (not built yet): branded invite emails

Phase 1 uses the Firebase password-reset email as the invite. For a proper
branded "X sent you a voucher" email, install the **Trigger Email** Firebase
extension with an SMTP provider, then add one
`db.collection('mail').add({...})` call after `provisionEmailAccount()`
succeeds.

## How send-to-anyone works (for maintainers)

- **Email recipients** get a real Firebase Auth account at send time, created
  through a secondary Firebase app (so the sender stays signed in) with a
  throwaway random password that is never stored. A fresh NaCl keypair is
  written to their user doc (`provisional: true`, plaintext `secretKey` —
  the same legacy key model `loadEncryptionKeys` already handles and upgrades
  on first sign-in). The password-reset email is their invitation. If the doc
  write fails, the Auth user is deleted again so nothing is orphaned.
- **Phone recipients** can't be pre-registered from the client (no admin SDK,
  no SMS), so they get a `pending-users/{phone}` placeholder keypair instead.
  Promises are encrypted to that placeholder and carry
  `receiverPhone`/`receiverId: null`. The sender is shown a claim link
  (`?claimPhone=+44...`) to share. When someone signs in with that phone
  number, the claim sweep decrypts each pending promise with the placeholder
  key, re-encrypts it for the claimer's own key, and deletes the placeholder —
  so the (shareable) placeholder secret can never read anything sent later.
- **Known limitation:** an email identity and a phone identity are separate
  accounts (different uids). They do not merge — a voucher sent to someone's
  email cannot be claimed by signing in with their phone number, and vice
  versa.
- Contact-adds (`addContact`) deliberately never provision accounts — a typo
  there must not create an account for, or email, a stranger.

## Manual test script (no automated tests in this repo)

1. **Regression:** send, transfer and redeem between two existing email
   accounts — behaviour unchanged.
2. **Fresh email:** send to an email with no account → confirm dialog →
   check the Auth user and `users` doc exist (publicKey, plaintext secretKey,
   `provisional: true`), the reset email arrives, and the sender stays
   signed in.
3. **Recipient onboarding:** recipient sets a password via the reset email and
   signs in → the promise decrypts (exercises the plaintext-secretKey
   fallback) and redeems.
4. **Google sign-in on the same email:** repeat test 3 but sign in with
   Google instead — same uid, keys intact, promise decrypts.
5. **Fresh phone:** send to a phone number with no account → pending doc +
   share modal appear. Open the claim link while signed out → phone number is
   prefilled. Sign in via OTP → the sweep claims the promise, it decrypts,
   the pending doc is deleted, and `phoneNumber` is backfilled on the users
   doc.
6. **Transfers:** transfer to a fresh email and to a fresh phone; then
   transfer a phone-claimed promise onward to an email user and confirm
   `receiverPhone` is cleared (stale phone routing dies).
7. **Failure drills:** cancel the confirm dialog (nothing is written);
   force a doc-write failure (rules) and confirm the compensating Auth-user
   delete; self-send to your own email and phone; a number typed without `+`
   is rejected with the country-code hint; quantity 5 to a fresh email
   creates one account and five promises.
