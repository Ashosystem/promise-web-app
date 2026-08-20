// OAuth Web Client ID from Firebase Console (Authentication > Sign-in method > Google > Web SDK config).
// Required for native Google Sign-In on Android.
const GOOGLE_WEB_CLIENT_ID = '508110234402-g2lcnqa1d7og0rk91eir0ks8j2tqmqb7.apps.googleusercontent.com';

// ===== ENCRYPTION UTILITY =====
class PromiseEncryption {
  /**
   * Generate a keypair for the user
   * Store the secret key in browser (not sent to Firebase)
   */
  static generateKeyPair() {
    return nacl.box.keyPair();
  }

  /**
   * Encrypt a message with a public key
   * Sender encrypts with recipient's public key
   */
  static encrypt(message, recipientPublicKey) {
    const messageUint8 = nacl.util.decodeUTF8(message);
    const publicKeyUint8 = nacl.util.decodeBase64(recipientPublicKey);

    // Generate ephemeral keypair for this encryption
    const ephemeralKeyPair = nacl.box.keyPair();

    // Encrypt
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const encrypted = nacl.box(
      messageUint8,
      nonce,
      publicKeyUint8,
      ephemeralKeyPair.secretKey
    );

    // Return: ephemeral public key + nonce + ciphertext (all base64)
    return {
      ephemeralPublicKey: nacl.util.encodeBase64(ephemeralKeyPair.publicKey),
      nonce: nacl.util.encodeBase64(nonce),
      ciphertext: nacl.util.encodeBase64(encrypted)
    };
  }

  /**
   * Decrypt with your secret key
   * Receiver decrypts with their own secret key
   */
  static decrypt(encryptedData, secretKey) {
    const ephemeralPublicKey = nacl.util.decodeBase64(encryptedData.ephemeralPublicKey);
    const nonce = nacl.util.decodeBase64(encryptedData.nonce);
    const ciphertext = nacl.util.decodeBase64(encryptedData.ciphertext);

    const decrypted = nacl.box.open(
      ciphertext,
      nonce,
      ephemeralPublicKey,
      secretKey
    );

    if (!decrypted) {
      throw new Error('Decryption failed - invalid key or corrupted data');
    }

    return nacl.util.encodeUTF8(decrypted);
  }
}

// ===== FIREBASE PROMISE APP =====
class FirebasePromiseApp {
  constructor() {
    this.currentUser = null;
    this.currentUserDoc = null;
    this.promises = new Map();
    this.contacts = new Map();
    this.myPools = new Map();
    this.poolUnsubscribers = new Map();
    this.selectedPoolId = null;
    this.selectedPoolDetailId = null;
    this.poolDetailTab = 'promises';
    this.activities = [];

    // My verified phone number (E.164), for phone-addressed promises. Stays
    // null until the phone identity work sets it from the users doc.
    this.myPhoneNumber = null;

    // Usernames
    this.currentUsername = null;
    this.usernames = new Map(); // email → username

    // Encryption
    this.myKeyPair = null;
    this.contactPublicKeys = new Map();
    this.keysLoading = false;  // ← ADD THIS LINE
    this.eventListenersInitialized = false;

    // Firebase references
    this.auth = firebase.auth();
    this.db = firebase.firestore();

    // Real-time listeners
    this.unsubscribers = [];

    console.log('Firebase initialized');
    this.initializeAuth();
  }

  // ===== AUTHENTICATION =====
    initializeAuth() {
      // Setup auth form listeners ONCE, not repeatedly
      const loginForm = document.getElementById('loginForm');
      const signupForm = document.getElementById('signupForm');
      const loginTab = document.getElementById('loginTab');
      const signupTab = document.getElementById('signupTab');

      if (loginForm && !loginForm.dataset.initialized) {
        loginForm.addEventListener('submit', (e) => {
          e.preventDefault();
          this.login();
        });
        loginForm.dataset.initialized = 'true';
      }

      if (signupForm && !signupForm.dataset.initialized) {
        signupForm.addEventListener('submit', (e) => {
          e.preventDefault();
          this.signup();
        });
        signupForm.dataset.initialized = 'true';
      }

      // Check for Google redirect result on load
      this.checkRedirectResult();

      // Claim-link entry (?claimPhone=+44...): prefill the phone sign-in with
      // the number the voucher was reserved for and nudge towards phone auth.
      const claimPhone = new URLSearchParams(location.search).get('claimPhone');
      if (claimPhone) {
        const phoneInput = document.getElementById('phoneNumber');
        if (phoneInput && !phoneInput.value) phoneInput.value = claimPhone;
        const phoneErrEl = document.getElementById('phoneAuthError');
        if (phoneErrEl) phoneErrEl.textContent = 'A voucher is waiting for this number — sign in with your phone to claim it.';
      }

      const googleBtn = document.getElementById('googleSignInBtn');
      if (googleBtn && !googleBtn.dataset.initialized) {
        googleBtn.addEventListener('click', () => this.signInWithGoogle());
        googleBtn.dataset.initialized = 'true';
      }

      const sendCodeBtn = document.getElementById('sendCodeBtn');
      if (sendCodeBtn && !sendCodeBtn.dataset.initialized) {
        sendCodeBtn.addEventListener('click', () => this.sendPhoneCode());
        sendCodeBtn.dataset.initialized = 'true';
      }

      const verifyCodeBtn = document.getElementById('verifyCodeBtn');
      if (verifyCodeBtn && !verifyCodeBtn.dataset.initialized) {
        verifyCodeBtn.addEventListener('click', () => this.verifyPhoneCode());
        verifyCodeBtn.dataset.initialized = 'true';
      }

      const backToPhoneBtn = document.getElementById('backToPhoneBtn');
      if (backToPhoneBtn && !backToPhoneBtn.dataset.initialized) {
        backToPhoneBtn.addEventListener('click', () => {
          document.getElementById('phoneStep2').classList.add('hidden');
          document.getElementById('phoneStep1').classList.remove('hidden');
          document.getElementById('phoneAuthError').textContent = '';
          this.recaptchaVerifier = null;
        });
        backToPhoneBtn.dataset.initialized = 'true';
      }

      if (loginTab && !loginTab.dataset.initialized) {
        loginTab.addEventListener('click', () => {
          this.switchAuthMode('login');
        });
        loginTab.dataset.initialized = 'true';
      }

      if (signupTab && !signupTab.dataset.initialized) {
        signupTab.addEventListener('click', () => {
          this.switchAuthMode('signup');
        });
        signupTab.dataset.initialized = 'true';
      }

      // Auth state monitoring
        this.auth.onAuthStateChanged(async (user) => {
            if (user) {
                this.currentUser = user;

                // Wait for DOM to be ready
                if (document.readyState === 'loading') {
                    await new Promise(resolve => {
                        document.addEventListener('DOMContentLoaded', resolve, { once: true });
                    });
                }

                this.showLoading();
                try {
                    await this.loadUserProfile();
                    await this.showApp();
                } catch (error) {
                    console.error('Failed to load profile:', error);
                    // Only show error if it's a genuine failure, not a timing issue
                    if (error.code || error.message.includes('permission') || error.message.includes('network')) {
                        this.showToast('Failed to load your data. Please refresh.', 'error');
                    }
                    this.hideLoading();
                }
            } else {
                this.showAuthScreen();
            }
        });



    }

  async login() {
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;

    try {
      this._pendingPassword = password;
      await this.auth.signInWithEmailAndPassword(email, password);
      // onAuthStateChanged will handle the rest; loadEncryptionKeys consumes _pendingPassword
    } catch (error) {
      this._pendingPassword = null;
      document.getElementById('loginError').textContent = error.message;
    }
  }

//    async signup() {
//        console.log('=== SIGNUP CALLED ===');
//        const email = document.getElementById('signupEmail').value;
//        const password = document.getElementById('signupPassword').value;
//        if (password.length < 6) {
//            document.getElementById('signupError').textContent = 'Password must be at least 6 characters';
//            return;
//        }
//        try {
//            console.log('Creating user with Firebase Auth...');
//            const userCred = await this.auth.createUserWithEmailAndPassword(email, password);
//            console.log('User created:', userCred.user.uid);
//
//            // Generate encryption keypair
//            this.myKeyPair = PromiseEncryption.generateKeyPair();
//            const publicKeyBase64 = nacl.util.encodeBase64(this.myKeyPair.publicKey);
//            const secretKeyBase64 = nacl.util.encodeBase64(this.myKeyPair.secretKey);
//
//            console.log('Creating Firestore user doc with public key...');
//            await this.db.collection('users').doc(userCred.user.uid).set({
//                email: email,
//                publicKey: publicKeyBase64,
//                createdAt: new Date().toISOString(),
//                updatedAt: new Date().toISOString()
//            });
//
//            // Store secret key in browser
//            this.storeSecretKeyLocally(secretKeyBase64);
//
//            console.log('User doc created successfully');
//            // onAuthStateChanged will handle the rest
//        } catch (error) {
//            console.error('SIGNUP ERROR:', error);
//            document.getElementById('signupError').textContent = error.message;
//        }
//    } ##OLD SIGN UP

    // NEW
    async signup() {
        console.log("SIGNUP CALLED");
        const email = document.getElementById("signupEmail").value;
        const password = document.getElementById("signupPassword").value;

        if (password.length < 6) {
            document.getElementById("signupError").textContent = "Password must be at least 6 characters";
            return;
        }

        try {
            console.log("Creating user with Firebase Auth...");
            const userCred = await this.auth.createUserWithEmailAndPassword(email, password);
            console.log("User created:", userCred.user.uid);

            // Generate encryption keypair
            this.myKeyPair = PromiseEncryption.generateKeyPair();
            const publicKeyBase64 = nacl.util.encodeBase64(this.myKeyPair.publicKey);
            const secretKeyBase64 = nacl.util.encodeBase64(this.myKeyPair.secretKey);

            console.log("Creating Firestore user doc with public key...");
            await this.db.collection("users").doc(userCred.user.uid).set({
                email: email,
                publicKey: publicKeyBase64,
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString()
            });

            // Store secret key in browser (local device cache)
            this.storeSecretKeyLocally(secretKeyBase64);

            // ALSO: encrypt secret key with password and store in Firestore for multi-device support
            try {
                await this.encryptAndStoreSecretKey(secretKeyBase64, password);
                console.log("Encrypted secret key stored in Firestore for recovery.");
            } catch (e) {
                // Do not block signup if this fails, but log it
                console.error("Failed to store encrypted secret key", e);
            }

            console.log("User doc created successfully. onAuthStateChanged will handle the rest.");
        } catch (error) {
            console.error("SIGNUP ERROR", error);
            document.getElementById("signupError").textContent = error.message;
        }
    }




  isNativePlatform() {
    const C = window.Capacitor;
    if (!C) return false;
    if (typeof C.isNativePlatform === 'function') return C.isNativePlatform();
    if (typeof C.getPlatform === 'function') return C.getPlatform() !== 'web';
    return false;
  }

  async signInWithGoogle() {
    const errEl = document.getElementById('loginError');
    errEl.textContent = '';
    try {
      if (this.isNativePlatform()) {
        await this.signInWithGoogleNative();
      } else {
        const provider = new firebase.auth.GoogleAuthProvider();
        await this.auth.signInWithPopup(provider);
      }
      // onAuthStateChanged handles the rest
    } catch (error) {
      const plat = (window.Capacitor && window.Capacitor.getPlatform) ? window.Capacitor.getPlatform() : 'unknown';
      errEl.textContent = `[${plat}] ${error.message || 'Google sign-in failed.'}`;
    }
  }

  async signInWithGoogleNative() {
    const SocialLogin = window.Capacitor.Plugins && window.Capacitor.Plugins.SocialLogin;
    if (!SocialLogin) throw new Error('SocialLogin plugin not available.');
    if (!this.socialLoginInitialized) {
      await SocialLogin.initialize({ google: { webClientId: GOOGLE_WEB_CLIENT_ID } });
      this.socialLoginInitialized = true;
    }
    // No custom scopes: default email/profile/openid come back without the
    // extra Authorization flow (which would require a modified MainActivity).
    const res = await SocialLogin.login({ provider: 'google', options: {} });
    const idToken = res && res.result && res.result.idToken;
    if (!idToken) throw new Error('No ID token returned from Google.');
    const credential = firebase.auth.GoogleAuthProvider.credential(idToken);
    await this.auth.signInWithCredential(credential);
  }

  async checkRedirectResult() {
    if (this.isNativePlatform()) return;
    try {
      const result = await this.auth.getRedirectResult();
      if (result && result.user) {
        // onAuthStateChanged handles the rest
      }
    } catch (error) {
      document.getElementById('loginError').textContent = error.message;
    }
  }

  initPhoneAuth() {
    if (this.recaptchaVerifier) return;
    this.recaptchaVerifier = new firebase.auth.RecaptchaVerifier('recaptcha-container', {
      size: 'invisible',
      callback: () => {}
    });
  }

  async sendPhoneCode() {
    const phone = document.getElementById('phoneNumber').value.trim();
    const errEl = document.getElementById('phoneAuthError');
    errEl.textContent = '';
    if (!phone) {
      errEl.textContent = 'Please enter a phone number with country code.';
      return;
    }
    try {
      this.initPhoneAuth();
      this.phoneConfirmationResult = await this.auth.signInWithPhoneNumber(phone, this.recaptchaVerifier);
      document.getElementById('phoneStep1').classList.add('hidden');
      document.getElementById('phoneStep2').classList.remove('hidden');
    } catch (error) {
      errEl.textContent = error.message;
      // Reset reCAPTCHA on failure so it can be retried
      this.recaptchaVerifier = null;
    }
  }

  async verifyPhoneCode() {
    const code = document.getElementById('smsCode').value.trim();
    const errEl = document.getElementById('phoneAuthError');
    errEl.textContent = '';
    if (!code) {
      errEl.textContent = 'Please enter the code.';
      return;
    }
    try {
      await this.phoneConfirmationResult.confirm(code);
      // onAuthStateChanged handles the rest
    } catch (error) {
      errEl.textContent = 'Invalid code. Please try again.';
    }
  }

  async logout() {
    // Clean up listeners
    this.unsubscribers.forEach(unsub => unsub());
    this.unsubscribers = [];
    await this.auth.signOut();
  }

  switchAuthMode(mode) {
    const loginForm = document.getElementById('loginForm');
    const signupForm = document.getElementById('signupForm');
    const loginTab = document.getElementById('loginTab');
    const signupTab = document.getElementById('signupTab');

    if (mode === 'login') {
        loginForm.style.display = 'block';
        signupForm.style.display = 'none';
        loginTab.classList.add('active');
        signupTab.classList.remove('active');
        document.getElementById('loginError').textContent = '';
    } else if (mode === 'signup') {
        loginForm.style.display = 'none';
        signupForm.style.display = 'block';
        loginTab.classList.remove('active');
        signupTab.classList.add('active');
        document.getElementById('signupError').textContent = '';
    }
  }


  // ===== ENCRYPTION HELPERS =====
    async loadEncryptionKeys() {
    this.keysLoading = true;
    try {
    // Load user doc to get their public key
    const userDocRef = this.db.collection('users').doc(this.currentUser.uid);
    const doc = await userDocRef.get();
    if (!doc.exists) return;

    // Try to get secret key from local storage first
    let storedSecretKey = localStorage.getItem(`prometheusSecretKey_${this.currentUser.uid}`);

    // If not found locally, try recovery via the password we just used to sign in (no prompt)
    if (!storedSecretKey && doc.data().encryptedSecretKey && this._pendingPassword) {
      try {
        storedSecretKey = await this.recoverSecretKeyFromPassword(this._pendingPassword);
        this.storeSecretKeyLocally(storedSecretKey);
        console.log('Secret key recovered using sign-in password');
      } catch (error) {
        console.warn('Sign-in password did not decrypt the stored secret key:', error);
      }
    }

    // Manual fallback: prompt for password / passphrase if we don't have one yet but encrypted key exists
    if (!storedSecretKey && doc.data().encryptedSecretKey) {
      const isGoogle = this.isGoogleUser();
      const promptText = isGoogle
        ? 'Enter your recovery passphrase to decrypt your promises on this device:'
        : 'Enter your account password to decrypt your promises on this device:';
      const secret = prompt(promptText);
      if (secret) {
        try {
          storedSecretKey = await this.recoverSecretKeyFromPassword(secret);
          this.storeSecretKeyLocally(storedSecretKey);
        } catch (error) {
          console.error('Failed to recover key:', error);
          alert(isGoogle ? 'Wrong passphrase, or no recovery passphrase was set on this account.' : 'Could not recover encryption key. Wrong password?');
        }
      }
    }

    // Legacy fallback: plaintext secret key in Firestore (older accounts)
    if (!storedSecretKey && doc.data().secretKey) {
      storedSecretKey = doc.data().secretKey;
      this.storeSecretKeyLocally(storedSecretKey);
      console.log('Secret key loaded from Firestore plaintext fallback');
    }

    // Capture pending password for backfill, then clear it
    const passwordForBackfill = this._pendingPassword;
    this._pendingPassword = null;

    if (storedSecretKey) {
      this.myKeyPair = {
        publicKey: nacl.util.decodeBase64(doc.data().publicKey),
        secretKey: nacl.util.decodeBase64(storedSecretKey)
      };
      // Backfill: if plaintext key was missing from Firestore, save it so other devices can decrypt
      if (!doc.data().secretKey) {
        await userDocRef.update({ secretKey: storedSecretKey, updatedAt: new Date().toISOString() });
      }
      // Backfill: if encrypted key is missing and we have the password, store it for proper cross-device recovery
      if (!doc.data().encryptedSecretKey && passwordForBackfill) {
        try { await this.encryptAndStoreSecretKey(storedSecretKey, passwordForBackfill); } catch (e) { console.warn('encrypt+store backfill failed', e); }
      }
    } else if (doc.data().publicKey) {
      // We have a public key but no secret key — DO NOT rotate. Past promises stay encrypted.
      // Surface a clear message instead of silently destroying the keypair.
      console.warn('No secret key available — entering read-only encrypted mode');
      this.myKeyPair = null;
      this.showToast('Cannot decrypt your promises on this device — wrong password or no encrypted key on file. Sign in on the original device (the one you signed up on) to restore.', 'error');
    } else {
      // Brand new account — no keys at all. Generate fresh pair (safe; no past data exists).
      console.log('First-time keypair generation for new account');
      this.myKeyPair = PromiseEncryption.generateKeyPair();
      const newPublicKey = nacl.util.encodeBase64(this.myKeyPair.publicKey);
      const newSecretKey = nacl.util.encodeBase64(this.myKeyPair.secretKey);
      await userDocRef.update({ publicKey: newPublicKey, secretKey: newSecretKey, updatedAt: new Date().toISOString() });
      this.storeSecretKeyLocally(newSecretKey);
      if (this.currentUserDoc) this.currentUserDoc.publicKey = newPublicKey;
    }
    console.log('Encryption keys loaded');
    } catch (error) {
    console.error('Error loading encryption keys:', error);
    } finally {
    this.keysLoading = false;
    }
  }


  isGoogleUser() {
    return !!(this.currentUser && this.currentUser.providerData && this.currentUser.providerData.some(p => p.providerId === 'google.com'));
  }

  async setupRecoveryPassphrase() {
    if (!this.myKeyPair || !this.myKeyPair.secretKey) {
      this.showToast('Cannot set up recovery: encryption keys not loaded.', 'error');
      return;
    }
    const userDoc = await this.db.collection('users').doc(this.currentUser.uid).get();
    if (userDoc.data() && userDoc.data().encryptedSecretKey) {
      const overwrite = confirm('A recovery passphrase is already set. Replacing it will not lose access to your promises, but old recovery codes will stop working. Continue?');
      if (!overwrite) return;
    }
    const passphrase = prompt('Choose a recovery passphrase (8+ characters). You will use this to sign in on other devices. WRITE IT DOWN — there is no way to recover it if lost.');
    if (!passphrase) return;
    if (passphrase.length < 8) { this.showToast('Passphrase must be at least 8 characters.', 'error'); return; }
    const confirmPhrase = prompt('Re-enter the passphrase to confirm:');
    if (passphrase !== confirmPhrase) { this.showToast('Passphrases did not match.', 'error'); return; }
    try {
      const secretKeyBase64 = nacl.util.encodeBase64(this.myKeyPair.secretKey);
      await this.encryptAndStoreSecretKey(secretKeyBase64, passphrase);
      this.showToast('Recovery passphrase set. You can now sign in on any device.', 'success');
      this.updateRecoveryButton();
    } catch (e) {
      console.error(e);
      this.showToast('Failed to set recovery passphrase.', 'error');
    }
  }

  async updateRecoveryButton() {
    const btn = document.getElementById('setupPassphraseBtn');
    if (!btn || !this.currentUser) return;
    try {
      const doc = await this.db.collection('users').doc(this.currentUser.uid).get();
      const hasRecovery = !!(doc.data() && doc.data().encryptedSecretKey);
      btn.textContent = hasRecovery ? 'Change recovery passphrase' : 'Set up cross-device recovery';
    } catch (e) { /* non-fatal */ }
  }

  storeSecretKeyLocally(secretKeyBase64) {
    // In production: encrypt this with the user's password using a KDF
    // For now: stored in browser (at rest it's still safer than sending to server)
    localStorage.setItem(`prometheusSecretKey_${this.currentUser.uid}`, secretKeyBase64);
  }

    // ===== PASSWORD-BASED KEY RECOVERY =====
    // Derive encryption key from password (for multi-device support)
    async deriveKeyFromPassword(password, userUid) {
      const encoder = new TextEncoder();
      const passwordData = encoder.encode(password);
      const saltData = encoder.encode(userUid); // Use UID as salt

      // Import password as key material
      const keyMaterial = await crypto.subtle.importKey(
        'raw',
        passwordData,
        'PBKDF2',
        false,
        ['deriveBits']
      );

      // Derive 32 bytes for NaCl secret key
      const derivedBits = await crypto.subtle.deriveBits(
        {
          name: 'PBKDF2',
          salt: saltData,
          iterations: 100000,
          hash: 'SHA-256'
        },
        keyMaterial,
        32 * 8 // 256 bits = 32 bytes
      );

      return new Uint8Array(derivedBits);
    }

    // Store encrypted secret key in Firestore (protected by password)
    async encryptAndStoreSecretKey(secretKeyBase64, password) {
      const derivedKey = await this.deriveKeyFromPassword(password, this.currentUser.uid);
      const secretKey = nacl.util.decodeBase64(secretKeyBase64);

      // Encrypt secret key with derived key
      const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
      const encrypted = nacl.secretbox(secretKey, nonce, derivedKey);

      // Store in Firestore
      await this.db.collection('users').doc(this.currentUser.uid).update({
        encryptedSecretKey: nacl.util.encodeBase64(encrypted),
        secretKeyNonce: nacl.util.encodeBase64(nonce)
      });
    }

    // Recover secret key from Firestore using password
    async recoverSecretKeyFromPassword(password) {
      const userDoc = await this.db.collection('users').doc(this.currentUser.uid).get();
      const data = userDoc.data();

      if (!data.encryptedSecretKey || !data.secretKeyNonce) {
        return null;
      }

      const derivedKey = await this.deriveKeyFromPassword(password, this.currentUser.uid);
      const encrypted = nacl.util.decodeBase64(data.encryptedSecretKey);
      const nonce = nacl.util.decodeBase64(data.secretKeyNonce);

      const decrypted = nacl.secretbox.open(encrypted, nonce, derivedKey);

      if (!decrypted) {
        throw new Error('Failed to recover key - wrong password?');
      }

      return nacl.util.encodeBase64(decrypted);
    }

        decryptPromiseContent(promise) {
            // Pool promises are plaintext — no decryption needed
            if (promise.isPoolPromise) {
                return promise.content || '[No content]';
            }
            // Check if keys are still loading
            if (this.keysLoading) {
                return '[Loading decryption keys...]';
            }

            if (!this.myKeyPair || !this.myKeyPair.secretKey) {
                return '[Encrypted - keys not loaded]';
            }

            // ✅ Determine which encrypted version to use based on user's role
            let encryptedData;

            if (promise.senderId === this.currentUser.uid) {
                // Current user is the SENDER
                // ✅ Use their archived copy (works across all devices)
                encryptedData = promise.contentEncryptedForSender;
            } else if (this.isCurrentReceiver(promise)) {
                // Current user is the RECEIVER
                encryptedData = promise.contentEncryptedForReceiver;
            } else {
                // User is neither sender nor receiver
                return '[Not authorized to view]';
            }

            // ✅ BACKWARD COMPATIBILITY: Fallback for old promises
            if (!encryptedData) {
                // Try old field names for promises created before this update
                if (promise.contentPlainForSender && promise.senderId === this.currentUser.uid) {
                    return promise.contentPlainForSender;
                }
                if (promise.contentEncrypted) {
                    // Old format: single encryption for receiver
                    encryptedData = promise.contentEncrypted;
                } else if (promise.content) {
                    return promise.content;
                } else {
                    return '[No content]';
                }
            }

            // ✅ Decrypt with user's secret key
            try {
                return PromiseEncryption.decrypt(encryptedData, this.myKeyPair.secretKey);
            } catch (error) {
                console.error('Failed to decrypt promise:', error);
                return '[Cannot decrypt - check your keys]';
            }
        }


  // ===== USER PROFILE =====
    async loadUserProfile() {
      const userDocRef = this.db.collection('users').doc(this.currentUser.uid);
      try {
        const doc = await userDocRef.get();
        if (doc.exists) {
          this.currentUserDoc = doc.data();
          // Migrate old accounts: add publicKey if missing
          if (!doc.data().publicKey) {
            this.myKeyPair = PromiseEncryption.generateKeyPair();
            const publicKeyBase64 = nacl.util.encodeBase64(this.myKeyPair.publicKey);
            const secretKeyBase64 = nacl.util.encodeBase64(this.myKeyPair.secretKey);

            await userDocRef.update({
              publicKey: publicKeyBase64,
              secretKey: secretKeyBase64,
              updatedAt: new Date().toISOString()
            });

            this.storeSecretKeyLocally(secretKeyBase64);
            this.currentUserDoc.publicKey = publicKeyBase64;
          }
        } else {
          // Create profile if doesn't exist
          this.myKeyPair = PromiseEncryption.generateKeyPair();
          const publicKeyBase64 = nacl.util.encodeBase64(this.myKeyPair.publicKey);
          const secretKeyBase64 = nacl.util.encodeBase64(this.myKeyPair.secretKey);

          await userDocRef.set({
            email: this.currentUser.email,
            phoneNumber: this.currentUser.phoneNumber || null,
            publicKey: publicKeyBase64,
            secretKey: secretKeyBase64,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
          });

          this.storeSecretKeyLocally(secretKeyBase64);
          this.currentUserDoc = (await userDocRef.get()).data();
        }
        // Load encryption keys
        await this.loadEncryptionKeys();
        await this.checkPendingInvites();
        await this.claimPhonePromises();
        // Nudge Google users to set a recovery passphrase if they don't have one yet
        if (this.isGoogleUser() && this.myKeyPair) {
          const u = await this.db.collection('users').doc(this.currentUser.uid).get();
          if (!u.data().encryptedSecretKey && !localStorage.getItem(`recoveryPromptDismissed_${this.currentUser.uid}`)) {
            setTimeout(() => {
              if (confirm('Set up a recovery passphrase now so you can sign in on other devices? You can also do this later from Settings.')) {
                this.setupRecoveryPassphrase();
              } else {
                localStorage.setItem(`recoveryPromptDismissed_${this.currentUser.uid}`, '1');
              }
            }, 1200);
          }
        }
      } catch (error) {
        console.error('Error loading user profile:', error);
      }
    }


  // ===== REAL-TIME LISTENERS =====
  setupRealtimeListeners() {
    console.log('Setting up real-time listeners...');

    // Listen to my promises (where I'm sender)
    console.log('Attaching sent promises listener...');
    const sentPromisesUnsub = this.db.collection('promises')
      .where('senderId', '==', this.currentUser.uid)
      .onSnapshot((snapshot) => {
        console.log('Sent promises snapshot received:', snapshot.size);
        snapshot.docChanges().forEach((change) => {
          const promiseData = { id: change.doc.id, ...change.doc.data() };
          if (change.type === 'added' || change.type === 'modified') {
            this.promises.set(promiseData.id, promiseData);
          } else if (change.type === 'removed') {
            this.promises.delete(promiseData.id);
          }
        });
        this.updateUI();
      });
    this.unsubscribers.push(sentPromisesUnsub);

    // Also listen to promises where I'm the receiver
    console.log('Attaching received promises listener...');
    const receivedPromisesUnsub = this.db.collection('promises')
      .where('receiverEmail', '==', this.currentUser.email)
      .onSnapshot((snapshot) => {
        console.log('Received promises snapshot received:', snapshot.size);
        snapshot.docChanges().forEach((change) => {
          const promiseData = { id: change.doc.id, ...change.doc.data() };
          if (change.type === 'added' || change.type === 'modified') {
            this.promises.set(promiseData.id, promiseData);
          } else if (change.type === 'removed') {
            this.promises.delete(promiseData.id);
          }
        });
        this.updateUI();
      });
    this.unsubscribers.push(receivedPromisesUnsub);

    // Promises addressed to my phone number merge into the same Map —
    // duplicate delivery with the email listener is harmless (same doc id).
    if (this.myPhoneNumber) {
      console.log('Attaching phone promises listener...');
      const phonePromisesUnsub = this.db.collection('promises')
        .where('receiverPhone', '==', this.myPhoneNumber)
        .onSnapshot((snapshot) => {
          console.log('Phone promises snapshot received:', snapshot.size);
          snapshot.docChanges().forEach((change) => {
            const promiseData = { id: change.doc.id, ...change.doc.data() };
            if (change.type === 'added' || change.type === 'modified') {
              this.promises.set(promiseData.id, promiseData);
            } else if (change.type === 'removed') {
              this.promises.delete(promiseData.id);
            }
          });
          this.updateUI();
        });
      this.unsubscribers.push(phonePromisesUnsub);

      // Live claim: if someone reserves vouchers for my number while I'm
      // signed in, migrate them without waiting for the next sign-in.
      const pendingClaimUnsub = this.db.collection('pending-users').doc(this.myPhoneNumber)
        .onSnapshot((doc) => {
          if (doc.exists) {
            this.migratePendingPhonePromises(this.myPhoneNumber)
              .catch(e => console.error('Live phone claim failed:', e));
          }
        });
      this.unsubscribers.push(pendingClaimUnsub);
    }

    // Listen to my contacts
    console.log('Attaching contacts listener...');
    const contactsUnsub = this.db.collection('users')
      .doc(this.currentUser.uid)
      .collection('contacts')
      .onSnapshot(async (snapshot) => {
        console.log('Contacts snapshot received:', snapshot.size);
        this.contacts.clear();
        snapshot.forEach((doc) => {
          // Doc id is the contact's uid; keyed by email, falling back to
          // phone for contacts that have no email identity.
          const data = { id: doc.id, ...doc.data() };
          this.contacts.set(data.email || data.phone, data);
        });
        // Fetch usernames for all contacts
        const uids = snapshot.docs.map(d => d.id);
        if (uids.length > 0) {
          const chunks = [];
          for (let i = 0; i < uids.length; i += 10) chunks.push(uids.slice(i, i + 10));
          for (const chunk of chunks) {
            const res = await this.db.collection('users').where(firebase.firestore.FieldPath.documentId(), 'in', chunk).get();
            res.forEach(d => {
              if (d.data().username) this.usernames.set(d.data().email, d.data().username);
            });
          }
        }
        this.updateUI();
      });
    this.unsubscribers.push(contactsUnsub);

    // Listen to my joined pools
    console.log('Attaching pools listener...');
    const poolsUnsub = this.db.collection('users')
      .doc(this.currentUser.uid)
      .collection('pools')
      .onSnapshot((snapshot) => {
        snapshot.docChanges().forEach((change) => {
          const poolId = change.doc.id;
          const data = { id: poolId, ...change.doc.data() };
          if (change.type === 'added' || change.type === 'modified') {
            this.myPools.set(poolId, data);
            if (!this.poolUnsubscribers.has(poolId)) {
              this.attachPoolPromiseListener(poolId);
            }
          } else if (change.type === 'removed') {
            this.myPools.delete(poolId);
            const unsub = this.poolUnsubscribers.get(poolId);
            if (unsub) { unsub(); this.poolUnsubscribers.delete(poolId); }
            // Drop pool promises from local cache
            for (const [pid, p] of this.promises) {
              if (p.poolId === poolId) this.promises.delete(pid);
            }
          }
        });
        this.updateUI();
      });
    this.unsubscribers.push(poolsUnsub);

    // Live invite listener — process pool invites as they arrive without needing a restart
    const inviteUnsub = this.db.collection('pool-invites')
      .where('invitedEmail', '==', this.currentUser.email)
      .onSnapshot(async (snapshot) => {
        for (const change of snapshot.docChanges()) {
          if (change.type !== 'added') continue;
          const { poolId, poolName, invitedByEmail } = change.doc.data();
          const alreadyJoined = await this.db.collection('users')
            .doc(this.currentUser.uid).collection('pools').doc(poolId).get();
          if (!alreadyJoined.exists) {
            await this.db.collection('users')
              .doc(this.currentUser.uid).collection('pools').doc(poolId)
              .set({ poolId, name: poolName, joinedAt: new Date().toISOString(), invitedBy: invitedByEmail });
            this.db.collection('pools').doc(poolId).collection('activity').add({
              type: 'joined', by: this.currentUser.email, via: 'invite', invitedBy: invitedByEmail,
              timestamp: new Date().toISOString()
            }).catch(e => console.warn('activity write failed:', e));
            this.showToast(`Joined pool "${poolName}" (invited by ${invitedByEmail})`, 'success');
          }
          await change.doc.ref.delete();
        }
      });
    this.unsubscribers.push(inviteUnsub);

    console.log('All listeners attached');
  }

  attachPoolPromiseListener(poolId) {
    const unsub = this.db.collection('promises')
      .where('poolId', '==', poolId)
      .onSnapshot((snapshot) => {
        snapshot.docChanges().forEach((change) => {
          const promiseData = { id: change.doc.id, ...change.doc.data() };
          if (change.type === 'added' || change.type === 'modified') {
            this.promises.set(promiseData.id, promiseData);
          } else if (change.type === 'removed') {
            this.promises.delete(promiseData.id);
          }
        });
        this.updateUI();
      });
    this.poolUnsubscribers.set(poolId, unsub);
  }

  async createPool() {
    const nameInput = document.getElementById('createPoolName');
    const name = nameInput.value.trim();
    if (!name) {
      this.showToast('Please enter a pool name', 'error');
      return;
    }
    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'pool';
    const suffix = Math.random().toString(36).slice(2, 7);
    const poolId = `${slug}-${suffix}`;
    try {
      // Best-effort top-level pool registry (for future discovery / metadata).
      // Non-fatal if rules disallow it — joining still works via the user's subcollection.
      try {
        await this.db.collection('pools').doc(poolId).set({
          poolId: poolId,
          name: name,
          createdBy: this.currentUser.uid,
          createdByEmail: this.currentUser.email,
          createdAt: new Date().toISOString()
        });
      } catch (e) {
        console.warn('Top-level pool registry write failed (non-fatal):', e);
      }
      await this.db.collection('users')
        .doc(this.currentUser.uid)
        .collection('pools')
        .doc(poolId)
        .set({
          poolId: poolId,
          name: name,
          joinedAt: new Date().toISOString(),
          createdByMe: true
        });
      this.db.collection('pools').doc(poolId).collection('activity').add({
        type: 'created', by: this.currentUser.email, poolName: name, timestamp: new Date().toISOString()
      }).catch(e => console.warn('pool activity write failed:', e));
      nameInput.value = '';
      this.showToast(`Created pool "${name}" — ID: ${poolId}`, 'success');
      this.addActivity(`Created pool "${name}" (id: ${poolId})`);
      // Copy ID to clipboard for easy sharing
      if (navigator.clipboard) {
        navigator.clipboard.writeText(poolId).catch(() => {});
      }
    } catch (error) {
      console.error('Failed to create pool:', error);
      this.showToast('Failed to create pool', 'error');
    }
  }

  async joinPool() {
    const poolIdInput = document.getElementById('joinPoolId');
    const poolNameInput = document.getElementById('joinPoolName');
    const poolId = poolIdInput.value.trim();
    const poolName = (poolNameInput.value || poolId).trim();
    if (!poolId) {
      this.showToast('Please enter a pool ID', 'error');
      return;
    }
    try {
      await this.db.collection('users')
        .doc(this.currentUser.uid)
        .collection('pools')
        .doc(poolId)
        .set({
          poolId: poolId,
          name: poolName,
          joinedAt: new Date().toISOString()
        });
      this.db.collection('pools').doc(poolId).collection('activity').add({
        type: 'joined', by: this.currentUser.email, timestamp: new Date().toISOString()
      }).catch(e => console.warn('pool activity write failed:', e));
      poolIdInput.value = '';
      poolNameInput.value = '';
      this.showToast(`Joined pool "${poolName}"`, 'success');
      this.addActivity(`Joined pool "${poolName}"`);
    } catch (error) {
      console.error('Failed to join pool:', error);
      this.showToast('Failed to join pool', 'error');
    }
  }

  async leavePool(poolId) {
    try {
      this.db.collection('pools').doc(poolId).collection('activity').add({
        type: 'left', by: this.currentUser.email, timestamp: new Date().toISOString()
      }).catch(e => console.warn('pool activity write failed:', e));
      await this.db.collection('users')
        .doc(this.currentUser.uid)
        .collection('pools')
        .doc(poolId)
        .delete();
      this.showToast('Left pool', 'success');
      this.addActivity(`Left pool "${poolId}"`);
    } catch (error) {
      console.error('Failed to leave pool:', error);
      this.showToast('Failed to leave pool', 'error');
    }
  }

  async inviteToPool(poolId, poolName, email) {
    if (!email || !this.isValidEmail(email)) {
      this.showToast('Please enter a valid email', 'error');
      return;
    }
    if (email === this.currentUser.email) {
      this.showToast("You're already in this pool", 'error');
      return;
    }
    const userQuery = await this.db.collection('users').where('email', '==', email).get();
    if (userQuery.empty) {
      this.showToast('No account found for that email', 'error');
      return;
    }
    try {
      await this.db.collection('pool-invites').add({
        poolId,
        poolName,
        invitedEmail: email,
        invitedByEmail: this.currentUser.email,
        createdAt: new Date().toISOString(),
      });
      this.db.collection('pools').doc(poolId).collection('activity').add({
        type: 'invited', by: this.currentUser.email, invitee: email,
        timestamp: new Date().toISOString()
      }).catch(e => console.warn('activity write failed:', e));
      this.showToast(`Invited ${email} to "${poolName}"`, 'success');
    } catch (error) {
      console.error('Failed to send pool invite:', error);
      this.showToast('Failed to send invite', 'error');
    }
  }

  async checkPendingInvites() {
    try {
      const invites = await this.db.collection('pool-invites')
        .where('invitedEmail', '==', this.currentUser.email)
        .get();
      if (invites.empty) return;
      const batch = this.db.batch();
      for (const doc of invites.docs) {
        const { poolId, poolName, invitedByEmail } = doc.data();
        const alreadyJoined = await this.db.collection('users')
          .doc(this.currentUser.uid)
          .collection('pools')
          .doc(poolId)
          .get();
        if (!alreadyJoined.exists) {
          await this.db.collection('users')
            .doc(this.currentUser.uid)
            .collection('pools')
            .doc(poolId)
            .set({ poolId, name: poolName, joinedAt: new Date().toISOString(), invitedBy: invitedByEmail });
          this.db.collection('pools').doc(poolId).collection('activity').add({
            type: 'joined', by: this.currentUser.email, via: 'invite', invitedBy: invitedByEmail,
            timestamp: new Date().toISOString()
          }).catch(e => console.warn('activity write failed:', e));
          this.showToast(`Joined pool "${poolName}" (invited by ${invitedByEmail})`, 'success');
        }
        batch.delete(doc.ref);
      }
      await batch.commit();
    } catch (error) {
      console.error('Error checking pool invites:', error);
    }
  }

  // ===== PROMISE OPERATIONS =====
      async createPromise() {
      const content = document.getElementById('promiseContent').value.trim();
      const receiverInput = document.getElementById('promiseReceiver').value.trim()
          || document.getElementById('promiseReceiverSelect').value.trim();
      const expiration = document.getElementById('promiseExpiration').value;
      const locked = document.getElementById('promiseLock').checked;
      const quantity = parseInt(document.getElementById('promiseQuantity').value) || 1;

      if (!content) {
        this.showToast('Please fill in all required fields', 'error');
        return;
      }

      if (quantity < 1 || quantity > 1000) {
        this.showToast('Quantity must be between 1 and 1000', 'error');
        return;
      }

      // POOL BRANCH: pool promises are plaintext, addressed to a pool not a user
      if (this.selectedPoolId) {
        const poolId = this.selectedPoolId;
        const pool = this.myPools.get(poolId);
        this.showLoading();
        try {
          const poolTemplate = {
            poolId: poolId,
            poolName: pool ? pool.name : poolId,
            isPoolPromise: true,
            content: content,
            senderId: this.currentUser.uid,
            senderEmail: this.currentUser.email,
            originalCreatorId: this.currentUser.uid,
            originalCreatorEmail: this.currentUser.email,
            status: locked ? 'locked' : 'active',
            locked: locked,
            expiresAt: expiration ? new Date(expiration).toISOString() : null,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
          };
          if (quantity === 1) {
            await this.db.collection('promises').add(poolTemplate);
          } else {
            const batch = this.db.batch();
            for (let i = 0; i < quantity; i++) {
              const docRef = this.db.collection('promises').doc();
              batch.set(docRef, poolTemplate);
            }
            await batch.commit();
          }
          this.db.collection('pools').doc(poolId).collection('activity').add({
            type: 'posted', by: this.currentUser.email, content: content,
            quantity: quantity, timestamp: new Date().toISOString()
          }).catch(e => console.warn('pool activity write failed:', e));
          this.showToast(`Posted to pool "${poolTemplate.poolName}"`, 'success');
          this.addActivity(`Posted ${quantity} promise(s) to pool "${poolTemplate.poolName}"`);
          document.getElementById('createPromiseForm').reset();
          this.selectedPoolId = null;
          const ri = document.getElementById('promiseReceiver');
          if (ri) {
            ri.disabled = false;
            ri.placeholder = 'Type an email or phone number, or pick a contact below...';
          }
        } catch (error) {
          console.error('Pool promise error:', error);
          this.showToast('Failed to post pool promise', 'error');
        } finally {
          this.hideLoading();
        }
        return;
      }

      if (!receiverInput) {
        this.showToast('Please fill in all required fields', 'error');
        return;
      }

      this.showLoading();
      try {
        const recipient = await this.resolveRecipient(receiverInput, { provisionIfMissing: true });
        if (!recipient) return;

        const receiverLabel = recipient.receiverEmail || recipient.receiverPhone;

        // If the recipient was typed in (not an existing contact), add them to the
        // Network automatically so the user can grow their contacts from this screen.
        if (recipient.receiverId && !this.contacts.has(receiverLabel)) {
          try {
            await this.db.collection('users')
              .doc(this.currentUser.uid)
              .collection('contacts')
              .doc(recipient.receiverId)
              .set({
                email: recipient.receiverEmail,
                phone: recipient.receiverPhone,
                addedAt: new Date().toISOString()
              });
            this.addActivity(`Contact "${receiverLabel}" added`);
          } catch (e) {
            // Non-fatal — sending the promise still proceeds
            console.error('Failed to auto-add contact:', e);
          }
        }

        // ✅ Encrypt for receiver (only they can read it)
        const encryptedForReceiver = PromiseEncryption.encrypt(content, recipient.publicKey);
        // ✅ Encrypt for sender (archive - sender can read from any device)
        const encryptedForSender = PromiseEncryption.encrypt(content, this.currentUserDoc.publicKey);

        // ✅ BUILD THE PROMISE TEMPLATE (same for all copies)
        const promiseTemplate = {
          contentEncryptedForReceiver: encryptedForReceiver,
          contentEncryptedForSender: encryptedForSender,
          senderId: this.currentUser.uid,
          senderEmail: this.currentUser.email,
          originalCreatorId: this.currentUser.uid,
          originalCreatorEmail: this.currentUser.email,
          receiverId: recipient.receiverId,
          receiverEmail: recipient.receiverEmail,
          receiverPhone: recipient.receiverPhone,
          status: locked ? 'locked' : 'active',
          locked: locked,
          expiresAt: expiration ? new Date(expiration).toISOString() : null,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          transferHistory: []
        };

        // ✅ USE BATCH WRITE FOR MULTIPLE PROMISES
        if (quantity === 1) {
          // Single promise: use add() for simplicity
          await this.db.collection('promises').add(promiseTemplate);
          this.showToast('Promise created successfully', 'success');
          this.addActivity(`Promise created for ${receiverLabel}: "[encrypted]"`);
        } else {
          // Batch create multiple promises
          const batch = this.db.batch();
          for (let i = 0; i < quantity; i++) {
            const docRef = this.db.collection('promises').doc();
            batch.set(docRef, promiseTemplate);
          }
          await batch.commit();
          this.showToast(`${quantity} promises created successfully`, 'success');
          this.addActivity(`Batch created ${quantity} promises for ${receiverLabel}`);
        }

        document.getElementById('createPromiseForm').reset();

        // Pending phone recipient: hand the sender the claim link to pass on
        if (recipient.pending) this.sharePhoneClaimLink(recipient.receiverPhone);
      } catch (error) {
        this.showToast('Failed to create promise', 'error');
        console.error('Error:', error);
      } finally {
        this.hideLoading();
      }
    }




        async transferPromise() {
        console.log('=== TRANSFER CALLED ===');
        const promiseId = document.getElementById('transferPromiseSelect').value;
        // Free-text input wins; the contacts/pools dropdown fills it (or, for
        // pools, carries the pool: value itself while the input is disabled).
        const transferInputEl = document.getElementById('transferReceiverInput');
        const newReceiverRaw = (transferInputEl ? transferInputEl.value.trim() : '')
            || document.getElementById('transferReceiver').value;

        if (!promiseId || !newReceiverRaw) {
            this.showToast('Please select a promise and new receiver', 'error');
            return;
        }

        // Route to pool transfer if a pool was selected
        if (newReceiverRaw.startsWith('pool:')) {
            const poolId = newReceiverRaw.slice(5);
            document.getElementById('transferPromiseForm').reset();
            // Form reset doesn't undo the disable applied when the pool was picked
            if (transferInputEl) {
                transferInputEl.disabled = false;
                transferInputEl.placeholder = 'Type an email or phone number, or pick a contact below...';
            }
            await this.transferToPool(promiseId, poolId);
            return;
        }

        const promise = this.promises.get(promiseId);

        if (!promise) {
            this.showToast('Promise not found', 'error');
            return;
        }

        if (promise.locked) {
            this.showToast('Cannot transfer locked promise', 'error');
            return;
        }

        // Check if user is the current receiver
        if (!this.isCurrentReceiver(promise)) {
            this.showToast('Only the current receiver can transfer this promise', 'error');
            return;
        }

        this.showLoading();

        try {
            // Look up new receiver
            const recipient = await this.resolveRecipient(newReceiverRaw, { provisionIfMissing: true });
            if (!recipient) return;

            const newReceiverLabel = recipient.receiverEmail || recipient.receiverPhone;
            const newReceiverPublicKey = recipient.publicKey;

            // ✅ DECRYPT THE CONTENT
            // Current receiver (me) decrypts with their key
            if (!this.myKeyPair || !this.myKeyPair.secretKey) {
                this.showToast('Cannot transfer: encryption keys not loaded on this device', 'error');
                this.hideLoading();
                return;
            }

            let plainContent;

            // ✅ Use the correct encrypted version
            let encryptedData = promise.contentEncryptedForReceiver;

            // Fallback for old promises
            if (!encryptedData) {
                encryptedData = promise.contentEncrypted;
            }

            try {
                plainContent = PromiseEncryption.decrypt(encryptedData, this.myKeyPair.secretKey);
                console.log('Decrypted content successfully');
            } catch (error) {
                console.error('Failed to decrypt content for re-encryption:', error);
                this.showToast('Cannot transfer: unable to decrypt promise content', 'error');
                this.hideLoading();
                return;
            }

            // Safety check
            if (plainContent.startsWith('[') && plainContent.includes('encrypted')) {
                this.showToast('Cannot transfer: content not accessible', 'error');
                this.hideLoading();
                return;
            }

            // ✅ RE-ENCRYPT FOR NEW RECEIVER
            const newEncryptedForReceiver = PromiseEncryption.encrypt(plainContent, newReceiverPublicKey);

            // ✅ BUILD UPDATE OBJECT
            // Only update the receiver's copy
            // The sender's archive stays the same (they always have it)
            const updateData = {
                receiverId: recipient.receiverId,
                receiverEmail: recipient.receiverEmail,
                // Set (or clear) phone routing so a promise transferred away
                // from a phone identity stops appearing in that phone's inbox.
                receiverPhone: recipient.receiverPhone,
                contentEncryptedForReceiver: newEncryptedForReceiver,
                updatedAt: new Date().toISOString(),
                transferHistory: firebase.firestore.FieldValue.arrayUnion({
                    from: promise.receiverEmail || promise.receiverPhone || '',
                    to: newReceiverLabel,
                    timestamp: new Date().toISOString()
                })
            };

            // ✅ NOTE: contentEncryptedForSender is NOT changed
            // The original sender always keeps their archive copy
            // If promise gets transferred back to sender later, they can still decrypt it

            console.log('Updating promise in Firestore...');
            await this.db.collection('promises').doc(promiseId).update(updateData);
            console.log('Promise transferred successfully');

            document.getElementById('transferPromiseForm').reset();
            this.showToast('Promise transferred successfully', 'success');
            this.addActivity(`Promise transferred to ${newReceiverLabel}`);

            // Pending phone recipient: hand the sender the claim link to pass on
            if (recipient.pending) this.sharePhoneClaimLink(recipient.receiverPhone);
        } catch (error) {
            console.error('TRANSFER ERROR:', error);
            this.showToast('Failed to transfer promise: ' + error.message, 'error');
        } finally {
            this.hideLoading();
        }
    }



  displayName(email) {
    if (!email) return '';
    const username = this.usernames.get(email);
    return username ? `@${username}` : email;
  }

  originalCreator(promise) {
    return promise.originalCreatorEmail
      || promise.transferredFromEmail
      || promise.senderEmail
      || '';
  }

  poolIcon(size) {
    const s = size || '1em';
    return `<img src="swimming-pool.png" alt="" style="width:${s};height:${s};vertical-align:-3px;">`;
  }

  toggleSettings() {
    const panel = document.getElementById('settingsPanel');
    if (!panel) return;
    const isHidden = panel.style.display === 'none' || panel.style.display === '';
    panel.style.display = isHidden ? 'block' : 'none';
    if (isHidden) {
      const input = document.getElementById('usernameInput');
      if (input && this.currentUsername) input.value = this.currentUsername;
      this.updateRecoveryButton();
    }
  }

  async saveUsername(username) {
    username = username.trim().toLowerCase();
    if (!username) { this.showToast('Please enter a username', 'error'); return; }
    if (!/^[a-z0-9_]{3,20}$/.test(username)) {
      this.showToast('Username must be 3–20 chars: letters, numbers, underscores only', 'error');
      return;
    }
    if (username === this.currentUsername) {
      this.showToast('That is already your username', 'error');
      return;
    }
    this.showLoading();
    try {
      const taken = await this.db.collection('users').where('username', '==', username).get();
      if (!taken.empty) {
        this.showToast('Username already taken', 'error');
        this.hideLoading();
        return;
      }
      await this.db.collection('users').doc(this.currentUser.uid).update({ username });
      this.currentUsername = username;
      this.usernames.set(this.currentUser.email, username);
      document.getElementById('currentAgentKey').textContent = `@${username}`;
      this.showToast(`Username set to @${username}`, 'success');
      document.getElementById('settingsPanel').style.display = 'none';
    } catch (e) {
      this.showToast('Failed to save username: ' + e.message, 'error');
    } finally {
      this.hideLoading();
    }
  }

  showTransferUI(promiseId) {
    console.log('Showing transfer UI for promise:', promiseId);
    // Set the promise select to this promise
    document.getElementById('transferPromiseSelect').value = promiseId;
    // Switch to transfer tab
    this.switchTab('transfer');
  }

  async transferToPool(promiseId, poolId) {
    const promise = this.promises.get(promiseId);
    if (!promise) { this.showToast('Promise not found', 'error'); return; }
    if (promise.locked) { this.showToast('Cannot transfer locked promise', 'error'); return; }
    if (!this.isCurrentReceiver(promise)) {
      this.showToast('Only the current receiver can transfer this promise', 'error');
      return;
    }
    if (!this.myKeyPair || !this.myKeyPair.secretKey) {
      this.showToast('Cannot transfer: encryption keys not loaded', 'error');
      return;
    }

    this.showLoading();
    try {
      const encryptedData = promise.contentEncryptedForReceiver || promise.contentEncrypted;
      let plainContent;
      try {
        plainContent = PromiseEncryption.decrypt(encryptedData, this.myKeyPair.secretKey);
      } catch (e) {
        this.showToast('Cannot transfer: unable to decrypt promise content', 'error');
        this.hideLoading();
        return;
      }

      const pool = this.myPools.get(poolId);
      const poolName = pool ? (pool.name || poolId) : poolId;
      const now = new Date().toISOString();

      const batch = this.db.batch();

      batch.set(this.db.collection('promises').doc(), {
        isPoolPromise: true,
        poolId,
        content: plainContent,
        senderEmail: this.currentUser.email,
        senderId: this.currentUser.uid,
        originalCreatorEmail: promise.originalCreatorEmail || promise.senderEmail,
        originalCreatorId: promise.originalCreatorId || promise.senderId,
        status: 'active',
        createdAt: now,
        transferredFrom: promiseId,
        transferredFromEmail: promise.senderEmail,
      });

      batch.update(this.db.collection('promises').doc(promiseId), {
        status: 'transferred',
        transferredToPool: poolId,
        updatedAt: now,
      });

      await batch.commit();

      this.showToast(`Promise transferred to pool "${poolName}"`, 'success');
      this.addActivity(`Promise transferred to pool "${poolName}"`);
    } catch (error) {
      console.error('Transfer to pool error:', error);
      this.showToast('Failed to transfer to pool: ' + error.message, 'error');
    } finally {
      this.hideLoading();
    }
  }

  async redeemPoolPromise(promiseId) {
    const promise = this.promises.get(promiseId);
    if (!promise || !promise.isPoolPromise) { this.showToast('Promise not found', 'error'); return; }
    this.showLoading();
    try {
      const now = new Date().toISOString();
      const batch = this.db.batch();
      batch.update(this.db.collection('promises').doc(promiseId), {
        status: 'redeemed',
        redeemedBy: this.currentUser.email,
        redeemedAt: now,
      });
      batch.set(this.db.collection('pools').doc(promise.poolId).collection('activity').doc(), {
        type: 'redeemed',
        promiseId,
        content: promise.content,
        by: this.currentUser.email,
        timestamp: now,
      });
      await batch.commit();
      this.showToast('Pool promise redeemed', 'success');
    } catch (e) {
      this.showToast('Failed to redeem: ' + e.message, 'error');
    } finally {
      this.hideLoading();
    }
  }

  // Active trusted pools for a single pool, folded from its activity log.
  async getTrustedPoolsForPool(poolId) {
    const snap = await this.db.collection('pools').doc(poolId).collection('activity')
      .orderBy('timestamp', 'asc').get();
    const trusted = new Map();
    snap.docs.forEach(doc => {
      const e = doc.data();
      if (e.type === 'trusted-pool-added' && e.trustedPoolId) {
        trusted.set(e.trustedPoolId, { trustedPoolId: e.trustedPoolId, trustedPoolName: e.trustedPoolName || e.trustedPoolId, active: true });
      } else if (e.type === 'trusted-pool-removed' && e.trustedPoolId) {
        const prev = trusted.get(e.trustedPoolId);
        if (prev) prev.active = false;
      }
    });
    return Array.from(trusted.values()).filter(t => t.active);
  }

  async showPoolTransferUI(promiseId) {
    const promise = this.promises.get(promiseId);
    if (!promise) return;
    const contacts = Array.from(this.contacts.values());

    // One-hop only: a pool promise may move to the *source* pool's directly-trusted pools.
    let trustedPools = [];
    try { trustedPools = await this.getTrustedPoolsForPool(promise.poolId); }
    catch (e) { console.error('Failed to load trusted pools for transfer:', e); }

    if (contacts.length === 0 && trustedPools.length === 0) {
      this.showToast('No transfer targets yet — add a contact or a trusted pool first', 'error');
      return;
    }

    const contactOptions = contacts.map(c => {
      const label = c.email || c.phone;
      const name = this.usernames.get(c.email) ? `@${this.usernames.get(c.email)} (${c.email})` : label;
      return `<option value="${label}">${name}</option>`;
    }).join('');
    const poolOptions = trustedPools.map(t =>
      `<option value="pool:${t.trustedPoolId}">🤝 ${t.trustedPoolName || t.trustedPoolId}</option>`
    ).join('');
    const groups = [
      contactOptions ? `<optgroup label="Contacts">${contactOptions}</optgroup>` : '',
      poolOptions ? `<optgroup label="Trusted Pools">${poolOptions}</optgroup>` : '',
    ].join('');

    const modal = document.createElement('div');
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:1000';
    modal.innerHTML = `
      <div style="background:var(--bg-card,#1e2a3a);border-radius:12px;padding:24px;max-width:400px;width:90%;box-shadow:0 4px 24px rgba(0,0,0,0.4)">
        <h3 style="margin:0 0 12px;color:var(--text-primary,#e2e8f0)">Transfer Pledge</h3>
        <p style="margin:0 0 16px;font-size:0.9em;color:var(--text-secondary,#94a3b8)">"${promise.content}"</p>
        <select id="poolTransferRecipient" style="width:100%;margin-bottom:16px;padding:8px;border-radius:6px;border:1px solid var(--border,#334155);background:var(--bg-input,#0f172a);color:var(--text-primary,#e2e8f0)">
          <option value="">-- Select recipient --</option>
          ${groups}
        </select>
        <div style="display:flex;gap:8px">
          <button id="confirmPoolTransfer" class="btn btn--primary" style="flex:1">Transfer</button>
          <button id="cancelPoolTransfer" class="btn btn--secondary" style="flex:1">Cancel</button>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
    document.getElementById('confirmPoolTransfer').onclick = async () => {
      const recipient = document.getElementById('poolTransferRecipient').value;
      if (!recipient) { this.showToast('Select a recipient', 'error'); return; }
      document.body.removeChild(modal);
      if (recipient.startsWith('pool:')) {
        await this.transferPoolToPool(promiseId, recipient.slice(5));
      } else {
        await this.transferPoolPromise(promiseId, recipient);
      }
    };
    document.getElementById('cancelPoolTransfer').onclick = () => document.body.removeChild(modal);
  }

  // Move a pool promise from its current pool to a directly-trusted destination pool.
  // The promise stays a pool promise (group-as-account); origin lineage is preserved.
  async transferPoolToPool(promiseId, destPoolId) {
    const promise = this.promises.get(promiseId);
    if (!promise || !promise.isPoolPromise) { this.showToast('Promise not found', 'error'); return; }
    if (promise.status !== 'active') { this.showToast('Only active promises can be transferred', 'error'); return; }
    const sourcePoolId = promise.poolId;
    if (destPoolId === sourcePoolId) { this.showToast("Can't transfer a pool to itself", 'error'); return; }
    this.showLoading();
    try {
      const now = new Date().toISOString();
      const batch = this.db.batch();

      // New pool promise in the destination pool.
      batch.set(this.db.collection('promises').doc(), {
        isPoolPromise: true,
        poolId: destPoolId,
        content: promise.content,
        senderEmail: this.currentUser.email,
        senderId: this.currentUser.uid,
        originalCreatorEmail: promise.originalCreatorEmail || promise.senderEmail,
        originalCreatorId: promise.originalCreatorId || promise.senderId,
        status: 'active',
        createdAt: now,
        transferredFrom: promiseId,
        transferredFromPool: sourcePoolId,
      });

      // Retire the source-pool promise.
      batch.update(this.db.collection('promises').doc(promiseId), {
        status: 'transferred',
        transferredBy: this.currentUser.email,
        transferredToPool: destPoolId,
        updatedAt: now,
      });

      // Accountability: log the outgoing move in the source pool's activity (we're a member here).
      batch.set(this.db.collection('pools').doc(sourcePoolId).collection('activity').doc(), {
        type: 'transferred-to-pool',
        promiseId,
        content: promise.content,
        by: this.currentUser.email,
        toPoolId: destPoolId,
        timestamp: now,
      });

      await batch.commit();

      // Best-effort: log the arrival in the destination pool too. Non-fatal if rules disallow
      // writing to a pool we're not a member of — the new promise itself is already visible there.
      this.db.collection('pools').doc(destPoolId).collection('activity').add({
        type: 'received-from-pool',
        content: promise.content,
        by: this.currentUser.email,
        fromPoolId: sourcePoolId,
        timestamp: now,
      }).catch(e => console.warn('Could not log arrival in destination pool:', e.message));

      const destName = (this.myPools.get(destPoolId) || {}).name || destPoolId;
      this.showToast(`Promise transferred to pool "${destName}"`, 'success');
      this.addActivity(`Transferred a pool promise to "${destName}"`);
    } catch (e) {
      console.error('Pool-to-pool transfer error:', e);
      this.showToast('Failed to transfer to pool: ' + e.message, 'error');
    } finally {
      this.hideLoading();
    }
  }

  async transferPoolPromise(promiseId, recipientRaw) {
    const promise = this.promises.get(promiseId);
    if (!promise || !promise.isPoolPromise) { this.showToast('Promise not found', 'error'); return; }
    if (!this.myKeyPair) { this.showToast('Encryption keys not loaded', 'error'); return; }
    this.showLoading();
    try {
      const recipient = await this.resolveRecipient(recipientRaw, { provisionIfMissing: true });
      if (!recipient) return;
      const recipientLabel = recipient.receiverEmail || recipient.receiverPhone;
      const now = new Date().toISOString();

      const encryptedForRecipient = PromiseEncryption.encrypt(promise.content, recipient.publicKey);
      const encryptedForSender = PromiseEncryption.encrypt(promise.content, this.currentUserDoc.publicKey);

      const batch = this.db.batch();
      batch.set(this.db.collection('promises').doc(), {
        senderId: this.currentUser.uid,
        senderEmail: this.currentUser.email,
        originalCreatorEmail: promise.originalCreatorEmail || promise.senderEmail,
        originalCreatorId: promise.originalCreatorId || promise.senderId,
        receiverId: recipient.receiverId,
        receiverEmail: recipient.receiverEmail,
        receiverPhone: recipient.receiverPhone,
        contentEncryptedForReceiver: encryptedForRecipient,
        contentEncryptedForSender: encryptedForSender,
        status: 'active',
        locked: false,
        createdAt: now,
        transferHistory: [{ from: `pool:${promise.poolId}`, to: recipientLabel, timestamp: now }],
      });
      batch.update(this.db.collection('promises').doc(promiseId), {
        status: 'transferred',
        transferredBy: this.currentUser.email,
        transferredTo: recipientLabel,
        updatedAt: now,
      });
      batch.set(this.db.collection('pools').doc(promise.poolId).collection('activity').doc(), {
        type: 'transferred',
        promiseId,
        content: promise.content,
        by: this.currentUser.email,
        to: recipientLabel,
        timestamp: now,
      });
      await batch.commit();
      this.showToast(`Promise transferred to ${this.displayName(recipientLabel)}`, 'success');

      // Pending phone recipient: hand the sender the claim link to pass on
      if (recipient.pending) this.sharePhoneClaimLink(recipient.receiverPhone);
    } catch (e) {
      console.error('Pool transfer error:', e);
      this.showToast('Failed to transfer: ' + e.message, 'error');
    } finally {
      this.hideLoading();
    }
  }

  async redeemPromise(promiseId) {
    const promise = this.promises.get(promiseId);

    if (!promise) {
      this.showToast('Promise not found', 'error');
      return;
    }

    if (!this.isCurrentReceiver(promise)) {
      this.showToast('Only the receiver can redeem this promise', 'error');
      return;
    }

    this.showLoading();
    try {
      await this.db.collection('promises').doc(promiseId).update({
        status: 'redeemed',
        redeemedAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      });

      this.showToast('Promise redeemed successfully', 'success');
      this.addActivity(`Promise "${this.decryptPromiseContent(promise)}" redeemed`);
    } catch (error) {
      this.showToast('Failed to redeem promise', 'error');
      console.error('Error:', error);
    } finally {
      this.hideLoading();
    }
  }

  // ===== CONTACTS =====
    async addContact() {
        const raw = document.getElementById('contactName').value.trim();

        // Contact-adds never provision accounts — a typo here must not create
        // an account for (or email) a stranger. Only existing users resolve.
        const recipient = await this.resolveRecipient(raw, { provisionIfMissing: false });
        if (!recipient) return;

        try {
            const contactUserId = recipient.receiverId;
            const contactLabel = recipient.receiverEmail || recipient.receiverPhone;

            // Check if already in contacts
            const existingContact = await this.db.collection('users')
                .doc(this.currentUser.uid)
                .collection('contacts')
                .doc(contactUserId)
                .get();

            if (existingContact.exists) {
                this.showToast('Contact already added', 'info');
                return;
            }

            await this.db.collection('users')
                .doc(this.currentUser.uid)
                .collection('contacts')
                .doc(contactUserId)
                .set({
                    email: recipient.receiverEmail,
                    phone: recipient.receiverPhone,
                    addedAt: new Date().toISOString()
                });

            document.getElementById('addContactForm').reset();

            // ✅ Better message for self-contact
            if (contactUserId === this.currentUser.uid) {
                this.showToast('Added yourself as contact (for self-promises)', 'success');
            } else {
                this.showToast('Contact added successfully', 'success');
            }

            this.addActivity(`Contact "${contactLabel}" added`);

        } catch (error) {
            this.showToast('Failed to add contact', 'error');
            console.error('Error:', error);
        }
    }


  async removeContact(contactId, label) {
    try {
      await this.db.collection('users')
        .doc(this.currentUser.uid)
        .collection('contacts')
        .doc(contactId)
        .delete();

      this.showToast('Contact removed successfully', 'success');
      this.addActivity(`Contact "${label}" removed`);
    } catch (error) {
      this.showToast('Failed to remove contact', 'error');
      console.error('Error:', error);
    }
  }

  // ===== UI METHODS =====
    async showApp() {
    console.log('Showing app container');
    document.getElementById('authScreen').classList.add('hidden');
    document.getElementById('appContainer').classList.remove('hidden');
    // Load own username if set
    const userDoc = await this.db.collection('users').doc(this.currentUser.uid).get();
    if (userDoc.exists && userDoc.data().username) {
      this.currentUsername = userDoc.data().username;
      this.usernames.set(this.currentUser.email, this.currentUsername);
      document.getElementById('currentAgentKey').textContent = `@${this.currentUsername}`;
    } else {
      document.getElementById('currentAgentKey').textContent = this.currentUser.email;
    }

    // Setup app listeners ONCE
    if (!this.eventListenersInitialized) {
        console.log('Calling setupEventListeners...');
        this.setupEventListeners();
        this.eventListenersInitialized = true;
    }

    console.log('Setting up real-time listeners with timeout...');
    try {
        // Try to set up listeners with 5-second timeout
        await Promise.race([
            this.setupRealtimeListeners(),
            new Promise((_, reject) =>
                setTimeout(() => reject(new Error('Listeners timeout')), 5000)
            )
        ]);
        console.log('Real-time listeners ready');
    } catch (error) {
        console.warn('Listeners setup issue:', error.message);
        // Still continue - UI loads even if listeners timeout
    }

    console.log('Calling updateUI...');
    this.updateUI();

    console.log('App fully loaded');
    this.hideLoading();
   }




  showAuthScreen() {
    document.getElementById('authScreen').classList.remove('hidden');
    document.getElementById('appContainer').classList.add('hidden');
  }

        setupEventListeners() {
            // Logout button
            const logoutBtn = document.getElementById('logoutBtn');
            if (logoutBtn) {
                logoutBtn.addEventListener('click', () => this.logout());
            }

                // Sidebar navigation (replacing old nav-tab)
            document.querySelectorAll('.nav-item').forEach(navItem => {
                navItem.addEventListener('click', (e) => {
                    const tabName = e.currentTarget.dataset.tab;
                    this.switchTab(tabName);
                });
            });

            // FAB button to create promise
            const fabButton = document.getElementById('createPromiseFAB');
            if (fabButton) {
                fabButton.addEventListener('click', () => {
                    this.switchTab('create');
                });
            }

            // Quick action buttons
            const quickCreateBtn = document.getElementById('quickCreateBtn');
            if (quickCreateBtn) {
                quickCreateBtn.addEventListener('click', () => {
                    this.switchTab('create');
                });
            }

            const quickViewInboxBtn = document.getElementById('quickViewInboxBtn');
            if (quickViewInboxBtn) {
                quickViewInboxBtn.addEventListener('click', () => {
                    this.switchTab('inbox');
                });
            }

            // Filter buttons
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const filterContainer = e.target.closest('.promise-filters');
                    filterContainer.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                    e.target.classList.add('active');

                    // Get the current tab and filter value
                    const currentTab = document.querySelector('.tab-pane.active').id;
                    const filterValue = e.target.dataset.filter;
                    this.filterPromises(currentTab, filterValue);
                });
            });


            // Forms
            const createForm = document.getElementById('createPromiseForm');
            if (createForm) {
                createForm.addEventListener('submit', (e) => {
                    e.preventDefault();
                    this.createPromise();
                });
            }

            // "Choose an existing contact" dropdown fills the typeable recipient input
            const receiverSelect = document.getElementById('promiseReceiverSelect');
            const receiverInput = document.getElementById('promiseReceiver');
            if (receiverSelect) {
                receiverSelect.addEventListener('change', (e) => {
                    const val = e.target.value;
                    if (!val) {
                        this.selectedPoolId = null;
                        if (receiverInput) {
                            receiverInput.disabled = false;
                            receiverInput.placeholder = 'Type an email or phone number, or pick a contact below...';
                        }
                        return;
                    }
                    if (val.startsWith('pool:')) {
                        this.selectedPoolId = val.slice(5);
                        const pool = this.myPools.get(this.selectedPoolId);
                        if (receiverInput) {
                            receiverInput.value = '';
                            receiverInput.disabled = true;
                            receiverInput.placeholder = `🏊 Posting to pool "${pool ? pool.name : this.selectedPoolId}" (public)`;
                        }
                    } else {
                        this.selectedPoolId = null;
                        if (receiverInput) {
                            receiverInput.disabled = false;
                            receiverInput.value = val;
                            receiverInput.placeholder = 'Type an email or phone number, or pick a contact below...';
                        }
                    }
                });
            }
            if (receiverInput) {
                receiverInput.addEventListener('input', () => {
                    if (receiverInput.value) this.selectedPoolId = null;
                });
            }

            const usernameInput = document.getElementById('usernameInput');
            if (usernameInput) {
                usernameInput.addEventListener('keydown', (e) => {
                    if (e.key === 'Enter') { e.preventDefault(); this.saveUsername(usernameInput.value); }
                });
            }

            const transferForm = document.getElementById('transferPromiseForm');
            if (transferForm) {
                transferForm.addEventListener('submit', (e) => {
                    e.preventDefault();
                    this.transferPromise();
                });
            }

            // Transfer tab: the contacts/pools dropdown fills the typeable recipient
            // input. Picking a pool keeps pool: routing on the select itself — the
            // input is cleared and disabled so the pool choice can't be shadowed.
            const transferReceiverSelect = document.getElementById('transferReceiver');
            const transferReceiverInput = document.getElementById('transferReceiverInput');
            if (transferReceiverSelect && transferReceiverInput) {
                transferReceiverSelect.addEventListener('change', (e) => {
                    const val = e.target.value;
                    if (val.startsWith('pool:')) {
                        const pool = this.myPools.get(val.slice(5));
                        transferReceiverInput.value = '';
                        transferReceiverInput.disabled = true;
                        transferReceiverInput.placeholder = `🏊 Transferring to pool "${pool ? pool.name : val.slice(5)}"`;
                    } else {
                        transferReceiverInput.disabled = false;
                        if (val) transferReceiverInput.value = val;
                        transferReceiverInput.placeholder = 'Type an email or phone number, or pick a contact below...';
                    }
                });
            }

            const createPoolForm = document.getElementById('createPoolForm');
            if (createPoolForm) {
                createPoolForm.addEventListener('submit', (e) => {
                    e.preventDefault();
                    this.createPool();
                });
            }

            const joinPoolForm = document.getElementById('joinPoolForm');
            if (joinPoolForm) {
                joinPoolForm.addEventListener('submit', (e) => {
                    e.preventDefault();
                    this.joinPool();
                });
            }

            const contactForm = document.getElementById('addContactForm');
            if (contactForm) {
                contactForm.addEventListener('submit', (e) => {
                    e.preventDefault();
                    this.addContact();
                });
            }

            // Event delegation for promise actions
            document.addEventListener('click', (e) => {
                if (e.target.matches('[data-action="redeem"]')) {
                    const promiseId = e.target.dataset.id;
                    this.redeemPromise(promiseId);
                } else if (e.target.matches('[data-action="transfer"]')) {
                    const promiseId = e.target.dataset.id;
                    this.showTransferUI(promiseId);
                } else if (e.target.matches('[data-action="pool-redeem"]')) {
                    this.redeemPoolPromise(e.target.dataset.id);
                } else if (e.target.matches('[data-action="pool-transfer"]')) {
                    this.showPoolTransferUI(e.target.dataset.id);
                }
            });


            // ✅ ADD THIS: Transfer promise select preview (set up ONCE, not on every update)
            const transferSelect = document.getElementById('transferPromiseSelect');
            if (transferSelect) {
                transferSelect.addEventListener('change', (e) => {
                    const promiseId = e.target.value;
                    const previewContainer = document.getElementById('transferPreview');

                    if (!promiseId || !previewContainer) {
                        if (previewContainer) previewContainer.innerHTML = '';
                        return;
                    }

                    const promise = this.promises.get(promiseId);
                    if (promise) {
                        previewContainer.innerHTML = `
                            <div class="preview-box">
                                <strong>Promise:</strong> ${this.decryptPromiseContent(promise)}<br>
                                <strong>From:</strong> ${promise.senderEmail}<br>
                                <strong>Current Receiver:</strong> ${promise.receiverEmail || promise.receiverPhone || ''}
                            </div>
                        `;
                    }
                });
            }
        }


      switchTab(tabName) {
      // Update nav items (sidebar)
      document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
      });
      document.querySelector(`.nav-item[data-tab="${tabName}"]`)?.classList.add('active');

      // Update tab panes
      document.querySelectorAll('.tab-pane').forEach(pane => {
        pane.classList.remove('active');
      });
      document.getElementById(tabName)?.classList.add('active');

      // Call appropriate update function
      switch (tabName) {
        case 'dashboard':
          this.updateDashboard();
          break;
        case 'inbox':
          this.updateInbox();
          break;
        case 'outbox':
          this.updateOutbox();
          break;
        case 'redeemed':
          this.updateRedeemed();
          break;
        case 'expired':
          this.updateExpired();
          break;
        case 'create':
          this.updateCreatePromiseForm();
          break;
        case 'contacts':
          this.updateContactsList();
          break;
        case 'pools':
          this.updatePoolsView();
          break;
      }
    }


      updateUI() {
       // ✅ POPULATE TRANSFER PROMISE SELECT
      const transferSelect = document.getElementById('transferPromiseSelect');
      if (transferSelect) {
        transferSelect.innerHTML = '<option value="">-- Select a promise to transfer --</option>';

        // Only show promises YOU received (not locked, not redeemed, not transferred)
        Array.from(this.promises.values())
          .filter(p => this.isCurrentReceiver(p) && p.status !== 'redeemed' && p.status !== 'transferred' && !p.locked)
          .forEach(promise => {
            const label = this.decryptPromiseContent(promise).substring(0, 50);
            const option = document.createElement('option');
            option.value = promise.id;
            option.textContent = `"${label}..." from ${promise.senderEmail}`;
            transferSelect.appendChild(option);
          });
      }

      // ✅ POPULATE TRANSFER RECEIVER CONTACTS + POOLS DROPDOWN
        const transferReceiver = document.getElementById('transferReceiver');
        if (transferReceiver) {
          transferReceiver.innerHTML = '<option value="">-- Select a contact --</option>';

          Array.from(this.contacts.values())
            .forEach(contact => {
              const label = contact.email || contact.phone;
              const option = document.createElement('option');
              option.value = label;
              option.textContent = this.usernames.get(contact.email) ? `@${this.usernames.get(contact.email)} (${contact.email})` : label;
              transferReceiver.appendChild(option);
            });

          if (this.myPools.size > 0) {
            const group = document.createElement('optgroup');
            group.label = 'My Pools';
            Array.from(this.myPools.values()).forEach(pool => {
              const option = document.createElement('option');
              option.value = `pool:${pool.poolId}`;
              option.textContent = `🏊 ${pool.name || pool.poolId}`;
              group.appendChild(option);
            });
            transferReceiver.appendChild(group);
          }
        }

      const currentPane = document.querySelector('.tab-pane.active');
      if (!currentPane) return;

      const currentTab = currentPane.id;

      // Update based on active tab to avoid unnecessary re-renders
      switch(currentTab) {
        case 'dashboard':
          this.updateDashboard();
          break;
        case 'inbox':
          this.updateInbox();
          break;
        case 'outbox':
          this.updateOutbox();
          break;
        case 'redeemed':
          this.updateRedeemed();
          break;
        case 'expired':
          this.updateExpired();
          break;
        case 'create':
          this.updateCreatePromiseForm();
          break;
        case 'contacts':
          this.updateContactsList();
          break;
        case 'pools':
          this.updatePoolsView();
          break;
      }

      this.updateBadges();
    }

        updateBadges() {
          const all = Array.from(this.promises.values());

          // Inbox: active promises received by me
          const inboxCount = all
            .filter(p => this.isCurrentReceiver(p) && this.isActive(p))
            .length;

          // Outbox: active promises I sent
          const outboxCount = all
            .filter(p => p.senderId === this.currentUser.uid && this.isActive(p))
            .length;

          // Redeemed / Expired: mine (sent or received), in that end-state
          const redeemedCount = all
            .filter(p => this.isMine(p) && p.status === 'redeemed')
            .length;

          const expiredCount = all
            .filter(p => this.isMine(p) && this.isExpired(p))
            .length;

          // Count contacts
          const networkCount = this.contacts.size;

          // Pools count
          const poolsCount = this.myPools.size;

          const inboxBadge = document.getElementById('inboxBadge');
          const outboxBadge = document.getElementById('outboxBadge');
          const redeemedBadge = document.getElementById('redeemedBadge');
          const expiredBadge = document.getElementById('expiredBadge');
          const networkBadge = document.getElementById('networkBadge');
          const poolsBadge = document.getElementById('poolsBadge');

          if (inboxBadge) inboxBadge.textContent = inboxCount > 0 ? inboxCount : '';
          if (outboxBadge) outboxBadge.textContent = outboxCount > 0 ? outboxCount : '';
          if (redeemedBadge) redeemedBadge.textContent = redeemedCount > 0 ? redeemedCount : '';
          if (expiredBadge) expiredBadge.textContent = expiredCount > 0 ? expiredCount : '';
          if (networkBadge) networkBadge.textContent = networkCount > 0 ? networkCount : '';
          if (poolsBadge) poolsBadge.textContent = poolsCount > 0 ? poolsCount : '';
        }

    updateInbox() {
      const container = document.getElementById('inboxPromises');
      if (!container) return;

      // Inbox shows only ACTIVE received promises — redeemed/expired move to their own tabs
      const receivedPromises = Array.from(this.promises.values())
        .filter(p => this.isCurrentReceiver(p) && this.isActive(p))
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

      if (receivedPromises.length === 0) {
        container.innerHTML = `
          <div class="empty-state">
            <p>📥 No active promises received</p>
            <small>Promises sent to you will appear here</small>
          </div>
        `;
        return;
      }

      container.innerHTML = receivedPromises
        .map(p => this.renderPromiseCard(p, true))
        .join('');
    }

    updateOutbox() {
      const container = document.getElementById('outboxPromises');
      if (!container) return;

      // Outbox shows only ACTIVE sent promises — redeemed/expired move to their own tabs
      const sentPromises = Array.from(this.promises.values())
        .filter(p => p.senderId === this.currentUser.uid && this.isActive(p))
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

      if (sentPromises.length === 0) {
        container.innerHTML = `
          <div class="empty-state">
            <p>📤 No active promises sent</p>
            <small>Create your first promise to get started</small>
          </div>
        `;
        return;
      }

      container.innerHTML = sentPromises
        .map(p => this.renderPromiseCard(p, false))
        .join('');
    }

    // Redeemed: every promise of mine (sent or received) that has been redeemed
    updateRedeemed() {
      const container = document.getElementById('redeemedList');
      if (!container) return;

      const redeemedPromises = Array.from(this.promises.values())
        .filter(p => this.isMine(p) && p.status === 'redeemed')
        .sort((a, b) => new Date(b.redeemedAt || b.updatedAt || b.createdAt) - new Date(a.redeemedAt || a.updatedAt || a.createdAt));

      if (redeemedPromises.length === 0) {
        container.innerHTML = `
          <div class="empty-state">
            <p>✅ No redeemed promises yet</p>
            <small>Promises you or others redeem will be collected here</small>
          </div>
        `;
        return;
      }

      container.innerHTML = redeemedPromises
        .map(p => this.renderPromiseCard(p, this.isCurrentReceiver(p)))
        .join('');
    }

    // Expired: every promise of mine (sent or received) past its expiry that was never redeemed
    updateExpired() {
      const container = document.getElementById('expiredPromises');
      if (!container) return;

      const expiredPromises = Array.from(this.promises.values())
        .filter(p => this.isMine(p) && this.isExpired(p))
        .sort((a, b) => new Date(b.expiresAt) - new Date(a.expiresAt));

      if (expiredPromises.length === 0) {
        container.innerHTML = `
          <div class="empty-state">
            <p>⏰ No expired promises</p>
            <small>Promises not redeemed before their expiry date will appear here</small>
          </div>
        `;
        return;
      }

      container.innerHTML = expiredPromises
        .map(p => this.renderPromiseCard(p, this.isCurrentReceiver(p)))
        .join('');
    }

    renderPromiseCard(promise, isInbox) {
      const content = this.decryptPromiseContent(promise);
      const expired = this.isExpired(promise);
      const statusClass = promise.status === 'redeemed' ? 'redeemed' : (expired ? 'expired' : (promise.locked ? 'locked' : ''));
      const statusText = promise.status === 'redeemed' ? '✅ Redeemed' : (expired ? '⏰ Expired' : (promise.locked ? '🔒 Locked' : '✨ Active'));

      const isReceiver = this.isCurrentReceiver(promise);
      // Expired or redeemed promises can no longer be acted on
      const canTransfer = isReceiver && !promise.locked && promise.status !== 'redeemed' && !expired;
      const canRedeem = isReceiver && promise.status !== 'redeemed' && !expired;

      const createdDate = new Date(promise.createdAt).toLocaleDateString();

      return `
        <div class="promise-card">
          <div class="promise-header">
            <span class="promise-status ${statusClass}">${statusText}</span>
          </div>

          <div class="promise-content">${content}</div>

          <div class="promise-meta">
            <div><strong>Created by:</strong> ${this.displayName(this.originalCreator(promise))} <span style="font-size:11px;color:var(--color-text-secondary);" title="Promises remain redeemable against their original creator">🔐</span></div>
            <div><strong>${isInbox ? 'From' : 'To'}:</strong> ${this.displayName(isInbox ? promise.senderEmail : (promise.receiverEmail || promise.receiverPhone))}</div>
            <div><strong>Created:</strong> ${createdDate}</div>
            ${promise.expiresAt ? `<div><strong>Expires:</strong> ${new Date(promise.expiresAt).toLocaleDateString()}</div>` : ''}
          </div>

          ${(canRedeem || canTransfer) ? `
            <div class="promise-actions">
                ${canRedeem ? `<button class="btn btn--primary btn--sm" data-action="redeem" data-id="${promise.id}">Redeem</button>` : ''}
                ${canTransfer ? `<button class="btn btn--secondary btn--sm" data-action="transfer" data-id="${promise.id}">Transfer</button>` : ''}
            </div>
          ` : ''}
        </div>
      `;
    }

    updatePoolsView() {
      const container = document.getElementById('poolsList');
      if (!container) return;
      if (this.selectedPoolDetailId) {
        this.renderPoolDetail(container, this.selectedPoolDetailId);
        return;
      }
      const pools = Array.from(this.myPools.values());
      if (pools.length === 0) {
        container.innerHTML = `
          <div class="empty-state">
            <p>${this.poolIcon('1.2em')} You haven't joined any pools yet</p>
            <small>Join a pool above to see public promises from its members</small>
          </div>
        `;
        return;
      }
      container.innerHTML = pools.map(pool => {
        const poolPromises = Array.from(this.promises.values())
          .filter(p => p.poolId === pool.id && this.isActive(p));
        const pid = pool.id;
        const safeName = pool.name.replace(/'/g, "\\'");
        return `
          <div class="pool-section" style="margin-bottom: var(--space-16);cursor:pointer;" onclick="app.openPoolDetail('${pid}')">
            <div class="pool-header" style="display:flex;justify-content:space-between;align-items:center;padding:var(--space-16);background:var(--color-surface);border-radius:8px;border:1px solid var(--color-border);transition:border-color 0.15s;" onmouseover="this.style.borderColor='var(--color-primary,#6366f1)'" onmouseout="this.style.borderColor='var(--color-border)'">
              <div>
                <strong style="font-size:16px;">${this.poolIcon('1.1em')} ${pool.name}</strong>
                <div style="font-size:12px;color:var(--color-text-secondary);margin-top:4px;">id: ${pid} · ${poolPromises.length} active promise${poolPromises.length === 1 ? '' : 's'}</div>
              </div>
              <div style="display:flex;align-items:center;gap:8px;">
                <span style="color:var(--color-text-secondary);font-size:13px;">Open →</span>
              </div>
            </div>
          </div>
        `;
      }).join('');
    }

    openPoolDetail(poolId) {
      this.selectedPoolDetailId = poolId;
      this.poolDetailTab = 'promises';
      this.updatePoolsView();
    }

    closePoolDetail() {
      this.selectedPoolDetailId = null;
      this.updatePoolsView();
    }

    renderPoolDetail(container, poolId) {
      const pool = this.myPools.get(poolId);
      if (!pool) { this.closePoolDetail(); return; }
      const poolPromises = Array.from(this.promises.values())
        .filter(p => p.poolId === poolId && this.isActive(p))
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
      const promisesHTML = poolPromises.length === 0
        ? `<div class="empty-state" style="padding:var(--space-24);"><p>No active promises in this pool yet</p></div>`
        : `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:var(--space-20);">${poolPromises.map(p => this.renderPoolPromiseCard(p)).join('')}</div>`;
      const safeName = pool.name.replace(/'/g, "\\'");
      const tab = this.poolDetailTab;
      const tabBtn = (key, label) => {
        const active = tab === key;
        return `<button onclick="app.switchPoolDetailTab('${key}')" style="background:none;border:none;cursor:pointer;padding:12px 20px;font-size:14px;border-bottom:2px solid ${active ? 'var(--color-primary,#6366f1)' : 'transparent'};color:${active ? 'var(--color-primary,#6366f1)' : 'var(--color-text-secondary)'};font-weight:${active ? '600' : '400'};">${label}</button>`;
      };
      container.innerHTML = `
        <div class="pool-detail" style="grid-column:1 / -1;width:min(96vw,1100px);margin:0 auto;display:flex;flex-direction:column;min-height:75vh;">
          <div style="display:flex;align-items:center;gap:12px;padding:var(--space-12);background:var(--color-surface);border:1px solid var(--color-border);border-radius:8px 8px 0 0;border-bottom:none;">
            <button onclick="app.closePoolDetail()" class="btn btn--sm btn--secondary" style="flex-shrink:0;">← Back</button>
            <div style="flex:1;min-width:0;">
              <div style="font-size:18px;font-weight:600;">${this.poolIcon('1.2em')} ${pool.name}</div>
              <div style="font-size:12px;color:var(--color-text-secondary);">id: ${poolId} · ${poolPromises.length} active</div>
            </div>
            <button onclick="app.leavePool('${poolId}'); app.closePoolDetail();" class="btn btn--sm btn--secondary">Leave</button>
          </div>
          <div style="display:flex;gap:8px;padding:8px var(--space-12);background:var(--color-surface);border:1px solid var(--color-border);border-top:none;border-bottom:none;">
            <input type="email" id="inviteInput-${poolId}" placeholder="Invite by email" class="form-control" style="flex:1;font-size:13px;">
            <button onclick="app.inviteToPool('${poolId}', '${safeName}', document.getElementById('inviteInput-${poolId}').value.trim()); document.getElementById('inviteInput-${poolId}').value='';" class="btn btn--sm btn--primary">Invite</button>
          </div>
          <div style="display:flex;background:var(--color-surface);border:1px solid var(--color-border);border-top:none;border-bottom:none;">
            ${tabBtn('promises', 'Promises')}
            ${tabBtn('activity', 'Activity')}
            ${tabBtn('members', 'Members')}
            ${tabBtn('trusted', 'Trusted Pools')}
          </div>
          <div style="flex:1;border:1px solid var(--color-border);border-top:none;border-radius:0 0 8px 8px;padding:var(--space-16);background:var(--color-background);min-height:400px;">
            ${tab === 'promises' ? promisesHTML : ''}
            ${tab === 'activity' ? `<div id="pool-detail-activity"><p style="color:var(--color-text-secondary)">Loading activity…</p></div>` : ''}
            ${tab === 'members' ? `<div id="pool-detail-members"><p style="color:var(--color-text-secondary)">Loading members…</p></div>` : ''}
            ${tab === 'trusted' ? `<div id="pool-detail-trusted"><p style="color:var(--color-text-secondary)">Loading trusted pools…</p></div>` : ''}
          </div>
        </div>
      `;
      if (tab === 'activity') this.loadPoolDetailActivity(poolId);
      if (tab === 'members') this.loadPoolDetailMembers(poolId);
      if (tab === 'trusted') this.loadPoolDetailTrusted(poolId);
    }

    switchPoolDetailTab(tab) {
      this.poolDetailTab = tab;
      this.updatePoolsView();
    }

    async loadPoolDetailActivity(poolId) {
      const panel = document.getElementById('pool-detail-activity');
      if (!panel) return;
      try {
        const snap = await this.db.collection('pools').doc(poolId).collection('activity')
          .orderBy('timestamp', 'desc').limit(100).get();
        if (snap.empty) {
          panel.innerHTML = '<p style="color:var(--color-text-secondary)">No activity yet.</p>';
          return;
        }
        panel.innerHTML = snap.docs.map(doc => {
          const entry = doc.data();
          return `<div style="padding:10px 0;border-bottom:1px solid var(--color-border);font-size:14px;line-height:1.5">${this.formatActivityEntry(entry)}</div>`;
        }).join('');
      } catch (e) {
        panel.innerHTML = '<p style="color:var(--color-text-secondary)">Could not load activity.</p>';
      }
    }

    async addTrustedPool(poolId) {
      const idInput = document.getElementById(`trustedPoolId-${poolId}`);
      const nameInput = document.getElementById(`trustedPoolName-${poolId}`);
      if (!idInput) return;
      const trustedPoolId = idInput.value.trim();
      const trustedPoolName = (nameInput && nameInput.value.trim()) || trustedPoolId;
      if (!trustedPoolId) {
        this.showToast('Please enter a pool ID to trust', 'error');
        return;
      }
      if (trustedPoolId === poolId) {
        this.showToast("A pool can't trust itself", 'error');
        return;
      }
      try {
        // Source of truth is the append-only activity log (same model as Members).
        await this.db.collection('pools').doc(poolId).collection('activity').add({
          type: 'trusted-pool-added', by: this.currentUser.email,
          trustedPoolId, trustedPoolName, timestamp: new Date().toISOString()
        });
        idInput.value = '';
        if (nameInput) nameInput.value = '';
        this.showToast(`Added trusted pool "${trustedPoolName}"`, 'success');
        this.addActivity(`Added trusted pool "${trustedPoolName}" to "${(this.myPools.get(poolId) || {}).name || poolId}"`);
        this.loadPoolDetailTrusted(poolId);
      } catch (error) {
        console.error('Failed to add trusted pool:', error);
        this.showToast('Failed to add trusted pool', 'error');
      }
    }

    async removeTrustedPool(poolId, trustedPoolId) {
      try {
        // Removal is an append (never delete) — preserves full traceability.
        await this.db.collection('pools').doc(poolId).collection('activity').add({
          type: 'trusted-pool-removed', by: this.currentUser.email,
          trustedPoolId, timestamp: new Date().toISOString()
        });
        this.showToast('Removed trusted pool', 'success');
        this.loadPoolDetailTrusted(poolId);
      } catch (error) {
        console.error('Failed to remove trusted pool:', error);
        this.showToast('Failed to remove trusted pool', 'error');
      }
    }

    async loadPoolDetailTrusted(poolId) {
      const panel = document.getElementById('pool-detail-trusted');
      if (!panel) return;
      const addBox = `
        <div style="display:flex;gap:8px;margin-bottom:8px;flex-wrap:wrap;">
          <input type="text" id="trustedPoolId-${poolId}" placeholder="Trusted pool ID (e.g. bristol-bakers-x1y2)" class="form-control" style="flex:2;min-width:200px;font-size:13px;">
          <input type="text" id="trustedPoolName-${poolId}" placeholder="Label (optional)" class="form-control" style="flex:1;min-width:120px;font-size:13px;">
          <button onclick="app.addTrustedPool('${poolId}')" class="btn btn--sm btn--primary">Add</button>
        </div>
        <p style="font-size:12px;color:var(--color-text-secondary);margin:0 0 var(--space-16);">Any member can add a trusted pool. Every change is recorded in this pool's activity log.</p>`;
      try {
        // Derive the current trusted set by folding add/remove events from the activity log.
        const snap = await this.db.collection('pools').doc(poolId).collection('activity')
          .orderBy('timestamp', 'asc').get();
        const trusted = new Map();
        snap.docs.forEach(doc => {
          const e = doc.data();
          if (e.type === 'trusted-pool-added' && e.trustedPoolId) {
            trusted.set(e.trustedPoolId, { trustedPoolId: e.trustedPoolId, trustedPoolName: e.trustedPoolName || e.trustedPoolId, addedBy: e.by, addedAt: e.timestamp, active: true });
          } else if (e.type === 'trusted-pool-removed' && e.trustedPoolId) {
            const prev = trusted.get(e.trustedPoolId);
            if (prev) prev.active = false;
          }
        });
        const list = Array.from(trusted.values()).filter(t => t.active)
          .sort((a, b) => new Date(b.addedAt) - new Date(a.addedAt));
        if (list.length === 0) {
          panel.innerHTML = addBox + '<p style="color:var(--color-text-secondary)">No trusted pools yet.</p>';
          return;
        }
        const rows = list.map(t => {
          const tid = t.trustedPoolId;
          const safeId = tid.replace(/'/g, "\\'");
          return `
            <div style="display:flex;align-items:center;justify-content:space-between;padding:12px 0;border-bottom:1px solid var(--color-border);">
              <div style="min-width:0;">
                <div style="font-size:14px;font-weight:500;">🤝 ${t.trustedPoolName || tid}</div>
                <div style="font-size:12px;color:var(--color-text-secondary);">id: ${tid} · added by ${this.displayName(t.addedBy)} · ${this.relativeTime(t.addedAt)}</div>
              </div>
              <button onclick="app.removeTrustedPool('${poolId}', '${safeId}')" class="btn btn--sm btn--secondary" style="flex-shrink:0;">Remove</button>
            </div>`;
        }).join('');
        panel.innerHTML = addBox + rows;
      } catch (e) {
        panel.innerHTML = addBox + '<p style="color:var(--color-text-secondary)">Could not load trusted pools.</p>';
      }
    }

    async loadPoolDetailMembers(poolId) {
      const panel = document.getElementById('pool-detail-members');
      if (!panel) return;
      try {
        const snap = await this.db.collection('pools').doc(poolId).collection('activity')
          .orderBy('timestamp', 'asc').get();
        const memberState = new Map();
        let creator = null;
        let creatorAt = null;
        snap.docs.forEach(doc => {
          const e = doc.data();
          if (!e.by) return;
          if (e.type === 'created') { creator = e.by; creatorAt = e.timestamp; }
          const prev = memberState.get(e.by);
          const wasMember = prev ? prev.member : false;
          if (e.type === 'left') {
            memberState.set(e.by, { member: false, firstSeen: prev ? prev.firstSeen : e.timestamp, lastSeen: e.timestamp });
          } else {
            memberState.set(e.by, { member: true, firstSeen: prev ? prev.firstSeen : e.timestamp, lastSeen: e.timestamp });
          }
        });
        if (creator && !memberState.has(creator)) memberState.set(creator, { member: true, firstSeen: creatorAt, lastSeen: creatorAt });
        const me = this.currentUser ? this.currentUser.email : null;
        if (me && !memberState.has(me) && this.myPools.has(poolId)) {
          memberState.set(me, { member: true, firstSeen: this.myPools.get(poolId).joinedAt || new Date().toISOString(), lastSeen: new Date().toISOString() });
        }
        const members = Array.from(memberState.entries())
          .filter(([_, s]) => s.member)
          .sort((a, b) => new Date(a[1].firstSeen) - new Date(b[1].firstSeen));
        if (members.length === 0) {
          panel.innerHTML = '<p style="color:var(--color-text-secondary)">No members detected yet from activity log.</p>';
          return;
        }
        const rows = members.map(([email, state]) => {
          const isCreator = email === creator;
          const isMe = email === me;
          const joined = this.relativeTime(state.firstSeen);
          return `
            <div style="display:flex;align-items:center;justify-content:space-between;padding:12px 0;border-bottom:1px solid var(--color-border);">
              <div>
                <div style="font-size:14px;">${this.displayName(email)} ${isMe ? '<span style="font-size:11px;color:var(--color-text-secondary);">(you)</span>' : ''}</div>
                <div style="font-size:12px;color:var(--color-text-secondary);">First seen ${joined}</div>
              </div>
              ${isCreator ? '<span style="font-size:11px;padding:3px 8px;background:var(--color-primary,#6366f1);color:white;border-radius:10px;">creator</span>' : ''}
            </div>
          `;
        }).join('');
        panel.innerHTML = `
          <div style="font-size:12px;color:var(--color-text-secondary);margin-bottom:12px;font-style:italic;">Membership is derived from the pool's activity log — members who never acted may not appear.</div>
          ${rows}
        `;
      } catch (e) {
        panel.innerHTML = '<p style="color:var(--color-text-secondary)">Could not load members.</p>';
      }
    }

    renderPoolPromiseCard(promise) {
      const content = promise.content || '[No content]';
      const expired = this.isExpired(promise);
      const isActive = promise.status === 'active' && !expired;
      const statusClass = promise.status === 'redeemed' ? 'redeemed' : (promise.status === 'transferred' ? 'redeemed' : (expired ? 'expired' : 'pool'));
      const statusText = promise.status === 'redeemed' ? `✅ Redeemed by ${this.displayName(promise.redeemedBy || '')}` : (promise.status === 'transferred' ? `↗️ Transferred by ${this.displayName(promise.transferredBy || '')}` : (expired ? '⏰ Expired' : `${this.poolIcon('1em')} Pool`));
      const createdDate = new Date(promise.createdAt).toLocaleDateString();
      return `
        <div class="promise-card">
          <div class="promise-header">
            <span class="promise-status ${statusClass}">${statusText}</span>
          </div>
          <div class="promise-content">${content}</div>
          <div class="promise-meta">
            <div><strong>Created by:</strong> ${this.displayName(this.originalCreator(promise))} <span style="font-size:11px;color:var(--color-text-secondary);" title="Promises remain redeemable against their original creator">🔐</span></div>
            ${promise.senderEmail !== this.originalCreator(promise) ? `<div><strong>Posted by:</strong> ${this.displayName(promise.senderEmail)}</div>` : `<div><strong>From:</strong> ${this.displayName(promise.senderEmail)}</div>`}
            <div><strong>Created:</strong> ${createdDate}</div>
            ${promise.expiresAt ? `<div><strong>Expires:</strong> ${new Date(promise.expiresAt).toLocaleDateString()}</div>` : ''}
          </div>
          ${isActive ? `
            <div class="promise-actions">
              <button class="btn btn--primary btn--sm" data-action="pool-redeem" data-id="${promise.id}">Redeem</button>
              <button class="btn btn--secondary btn--sm" data-action="pool-transfer" data-id="${promise.id}">Transfer</button>
            </div>
          ` : ''}
        </div>
      `;
    }

    updateContactsList() {
      const container = document.getElementById('contactsList');
      if (!container) return;

      if (this.contacts.size === 0) {
        container.innerHTML = '<p style="text-align: center; color: var(--color-text-secondary); padding: var(--space-32);">No contacts yet. Start building your network!</p>';
        return;
      }

      container.innerHTML = Array.from(this.contacts.values())
        .map(contact => {
          const label = contact.email || contact.phone;
          const username = this.usernames.get(contact.email);
          return `
            <div class="contact-card">
              <div class="contact-info">
                ${username ? `<div style="font-weight:600;margin-bottom:2px;">@${username}</div>` : ''}
                <div class="contact-email">${label}</div>
                <div style="font-size: 12px; color: var(--color-text-secondary);">Added ${new Date(contact.addedAt).toLocaleDateString()}</div>
              </div>
              <div class="contact-actions">
                <button onclick="app.removeContact('${contact.id}', '${label}')" class="btn btn--sm btn--secondary">Remove</button>
              </div>
            </div>
          `;
        }).join('');
    }

    filterPromises(tabId, filterValue) {
      // Inbox/Outbox only ever hold active promises now (redeemed/expired have their
      // own tabs), so "All" and "Active" resolve to the same live set.
      if (tabId === 'inbox') {
        const container = document.getElementById('inboxPromises');
        if (!container) return;

        const receivedPromises = Array.from(this.promises.values())
          .filter(p => this.isCurrentReceiver(p) && this.isActive(p))
          .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

        container.innerHTML = receivedPromises.length === 0
          ? `<div class="empty-state"><p>No active promises</p></div>`
          : receivedPromises.map(p => this.renderPromiseCard(p, true)).join('');
      }
      else if (tabId === 'outbox') {
        const container = document.getElementById('outboxPromises');
        if (!container) return;

        const sentPromises = Array.from(this.promises.values())
          .filter(p => p.senderId === this.currentUser.uid && this.isActive(p))
          .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

        container.innerHTML = sentPromises.length === 0
          ? `<div class="empty-state"><p>No active promises</p></div>`
          : sentPromises.map(p => this.renderPromiseCard(p, false)).join('');
      }
    }


  updateDashboard() {
    const sentPromises = Array.from(this.promises.values())
      .filter(p => p.senderId === this.currentUser.uid);

    const receivedPromises = Array.from(this.promises.values())
      .filter(p => this.isCurrentReceiver(p));

    const activeCount = Array.from(this.promises.values())
      .filter(p => this.isActive(p)).length;

    const redeemedCount = Array.from(this.promises.values())
      .filter(p => p.status === 'redeemed').length;

    document.getElementById('totalPromises').textContent = this.promises.size;
    document.getElementById('activePromises').textContent = activeCount;
    document.getElementById('redeemedPromises').textContent = redeemedCount;
    document.getElementById('networkAgents').textContent = this.contacts.size + 1;

    const activityContainer = document.getElementById('activityLog');
    if (this.activities.length === 0) {
      activityContainer.innerHTML = '<p>No recent activity</p>';
      return;
    }

    activityContainer.innerHTML = this.activities
      .slice(-5)
      .reverse()
      .map(activity => `<div class="activity-item">${activity}</div>`)
      .join('');
  }

  updateCreatePromiseForm() {
    // The "Send to" field is a typeable email input (datalist autocomplete) plus an
    // explicit dropdown of existing contacts that fills the input when chosen.
    const contacts = Array.from(this.contacts.values());

    const datalist = document.getElementById('contactOptions');
    if (datalist) {
      datalist.innerHTML = contacts
        .map(contact => `<option value="${contact.email || contact.phone}"></option>`)
        .join('');
    }

    const select = document.getElementById('promiseReceiverSelect');
    if (select) {
      const pools = Array.from(this.myPools.values());
      let html = '<option value="">— or choose an existing contact or pool —</option>';
      if (contacts.length > 0) {
        html += '<optgroup label="Contacts">' +
          contacts.map(c => {
            const label = c.email || c.phone;
            const name = this.usernames.get(c.email) ? `@${this.usernames.get(c.email)} (${c.email})` : label;
            return `<option value="${label}">${name}</option>`;
          }).join('') +
          '</optgroup>';
      }
      if (pools.length > 0) {
        html += '<optgroup label="Pools">' +
          pools.map(p => `<option value="pool:${p.id}">🏊 ${p.name}</option>`).join('') +
          '</optgroup>';
      }
      select.innerHTML = html;
    }
  }

  // ===== UTILITIES =====
  isValidEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
  }

  // ===== RECIPIENT RESOLUTION =====
  // Classify raw recipient input as an email address or an E.164 phone number.
  // Phone parsing is deliberately minimal (no libphonenumber): strip common
  // separators, turn a leading 00 into +, then require + followed by 7-15
  // digits. Numbers typed without a country code are rejected with a hint.
  normalizeRecipient(raw) {
    const value = (raw || '').trim();
    if (!value) return { kind: 'invalid', value: '' };
    if (value.includes('@')) {
      const email = value.toLowerCase();
      if (this.isValidEmail(email)) return { kind: 'email', value: email };
      return { kind: 'invalid', value: email, hint: 'Please enter a valid email address' };
    }
    let phone = value.replace(/[\s\-.()]/g, '');
    if (phone.startsWith('00')) phone = '+' + phone.slice(2);
    if (/^\+[1-9]\d{6,14}$/.test(phone)) return { kind: 'phone', value: phone };
    if (/^\d+$/.test(phone)) {
      return { kind: 'invalid', value: phone, hint: 'Include the country code, e.g. +447700900000' };
    }
    return { kind: 'invalid', value: value };
  }

  // Am I the current receiver of this promise? Matches on email or, for
  // phone-addressed promises, on my verified phone number.
  isCurrentReceiver(promise) {
    return (!!this.currentUser.email && promise.receiverEmail === this.currentUser.email)
      || (!!this.myPhoneNumber && promise.receiverPhone === this.myPhoneNumber);
  }

  // Resolve typed recipient input to a concrete receiver, or null (after a
  // toast) when the caller should abort. provisionIfMissing reserves the
  // account-provisioning path for send/transfer flows — never contact-adds.
  async resolveRecipient(raw, { provisionIfMissing = false } = {}) {
    const norm = this.normalizeRecipient(raw);
    if (norm.kind === 'invalid') {
      this.showToast(norm.hint || 'Enter a valid email address or phone number', 'error');
      return null;
    }

    if (norm.kind === 'email') {
      const query = await this.db.collection('users').where('email', '==', norm.value).get();
      if (!query.empty) {
        const doc = query.docs[0];
        return {
          kind: 'email',
          receiverId: doc.id,
          receiverEmail: norm.value,
          receiverPhone: null,
          publicKey: doc.data().publicKey,
          pending: false
        };
      }
      if (provisionIfMissing) {
        const ok = confirm(`No account exists for ${norm.value}. Create one and send the voucher there? They'll get an email to set their password.`);
        if (!ok) return null;
        return await this.provisionEmailAccount(norm.value);
      }
      this.showToast('Receiver not found', 'error');
      return null;
    }

    // Phone: sending to my own number resolves to my own account, mirroring
    // how self-promises to my own email already work.
    if (this.myPhoneNumber && norm.value === this.myPhoneNumber) {
      return {
        kind: 'phone',
        receiverId: this.currentUser.uid,
        receiverEmail: this.currentUser.email || null,
        receiverPhone: norm.value,
        publicKey: this.currentUserDoc.publicKey,
        pending: false
      };
    }
    const query = await this.db.collection('users').where('phoneNumber', '==', norm.value).get();
    if (!query.empty) {
      const doc = query.docs[0];
      return {
        kind: 'phone',
        receiverId: doc.id,
        receiverEmail: doc.data().email || null,
        receiverPhone: norm.value,
        publicKey: doc.data().publicKey,
        pending: false
      };
    }
    // Not a registered user — an earlier send may have left a placeholder.
    const pendingDoc = await this.db.collection('pending-users').doc(norm.value).get();
    if (pendingDoc.exists) {
      return {
        kind: 'phone',
        receiverId: null,
        receiverEmail: null,
        receiverPhone: norm.value,
        publicKey: pendingDoc.data().publicKey,
        pending: true
      };
    }
    if (provisionIfMissing) {
      const ok = confirm(`No account exists for ${norm.value}. Reserve the voucher for that number? You'll get a link to share so they can claim it by signing in with their phone.`);
      if (!ok) return null;
      return await this.provisionPhonePlaceholder(norm.value);
    }
    this.showToast('Receiver not found', 'error');
    return null;
  }

  // ===== ACCOUNT PROVISIONING (send-to-anyone) =====
  // Secondary Firebase app, so creating the recipient's account doesn't sign
  // the sender out — auth state is per-app. Lazy singleton.
  getProvisioningApp() {
    if (!this._provisioningApp) {
      this._provisioningApp = firebase.initializeApp(firebase.app().options, 'provisioning');
    }
    return this._provisioningApp;
  }

  // One-time password for the provisional account. Never stored anywhere —
  // the recipient takes ownership via the password-reset email.
  generateThrowawayPassword() {
    const bytes = new Uint8Array(24);
    crypto.getRandomValues(bytes);
    return nacl.util.encodeBase64(bytes);
  }

  // Create a real Firebase Auth account + users doc for an email address that
  // has no account yet, so a voucher can be encrypted to it immediately.
  // Runs before any promise write, so a failed provision never half-sends.
  // Returns a resolver-shaped recipient, or null (after a toast) on failure.
  async provisionEmailAccount(email) {
    const secApp = this.getProvisioningApp();
    const secAuth = secApp.auth();
    try {
      // Never persist the provisional session on this device.
      await secAuth.setPersistence(firebase.auth.Auth.Persistence.NONE);

      let cred;
      try {
        cred = await secAuth.createUserWithEmailAndPassword(email, this.generateThrowawayPassword());
      } catch (error) {
        if (error.code === 'auth/email-already-in-use') {
          this.showToast(`An account for ${email} already exists but couldn't be looked up. Ask them to sign in once, then send again.`, 'error');
        } else {
          this.showToast(`Could not create an account for ${email}: ${error.message}`, 'error');
        }
        return null;
      }

      // Keypair for the new account. The plaintext secretKey in Firestore
      // matches the legacy key model — loadEncryptionKeys picks it up on
      // their first sign-in and re-encrypts it under their new password.
      const keyPair = PromiseEncryption.generateKeyPair();
      const publicKey = nacl.util.encodeBase64(keyPair.publicKey);
      const secretKey = nacl.util.encodeBase64(keyPair.secretKey);
      const now = new Date().toISOString();
      try {
        // Written via the secondary app's Firestore: the write is authored by
        // the NEW uid, which is what owner-only create rules require.
        await secApp.firestore().collection('users').doc(cred.user.uid).set({
          email: email,
          publicKey: publicKey,
          secretKey: secretKey,
          provisional: true,
          invitedByEmail: this.currentUser.email || null,
          createdAt: now,
          updatedAt: now
        });
      } catch (error) {
        // Compensate: don't leave an Auth user with no keys behind.
        console.error('Provisioning doc write failed, deleting auth user:', error);
        try { await cred.user.delete(); } catch (e) { console.error('Compensating delete failed:', e); }
        this.showToast('Could not set up the new account (permissions?). Nothing was sent.', 'error');
        return null;
      }

      // Phase-1 notification: the password-reset email doubles as the invite.
      try {
        await secAuth.sendPasswordResetEmail(email);
      } catch (error) {
        console.warn('Password-reset email failed (non-fatal):', error);
        this.showToast(`Account created, but the invite email failed to send. Ask ${email} to use "Forgot password" when they first sign in.`, 'info');
      }

      return {
        kind: 'email',
        receiverId: cred.user.uid,
        receiverEmail: email,
        receiverPhone: null,
        publicKey: publicKey,
        pending: false
      };
    } finally {
      // Never stay signed in as the provisional user on the secondary app.
      try { await secAuth.signOut(); } catch (e) { /* non-fatal */ }
    }
  }

  // Client-side Firebase can't pre-create phone-auth accounts or send SMS, so
  // an unknown phone gets a pending-users placeholder keypair instead. The
  // real account migrates (re-encrypts) the promises on first sign-in.
  async provisionPhonePlaceholder(phone) {
    const keyPair = PromiseEncryption.generateKeyPair();
    const publicKey = nacl.util.encodeBase64(keyPair.publicKey);
    const secretKey = nacl.util.encodeBase64(keyPair.secretKey);
    try {
      await this.db.collection('pending-users').doc(phone).set({
        phone: phone,
        publicKey: publicKey,
        secretKey: secretKey,
        invitedByEmail: this.currentUser.email || null,
        createdAt: new Date().toISOString()
      });
    } catch (error) {
      console.error('Pending placeholder write failed:', error);
      this.showToast('Could not reserve the voucher for that number (permissions?). Nothing was sent.', 'error');
      return null;
    }
    return {
      kind: 'phone',
      receiverId: null,
      receiverEmail: null,
      receiverPhone: phone,
      publicKey: publicKey,
      pending: true
    };
  }

  // Public URL of the app for share links. Inside the Capacitor wrapper the
  // page origin is capacitor:// or file://, which nobody else can open — fall
  // back to the hosted deploy (the Pages workflow publishes www/ there).
  getAppUrl() {
    const HOSTED_URL = 'https://ashosystem.github.io/promise-web-app/';
    if (/^(capacitor|file|ionic):/.test(location.protocol)) return HOSTED_URL;
    return location.origin + location.pathname;
  }

  // After sending to a pending phone recipient: the app can't text them, so
  // hand the sender a claim link to pass on (share sheet / SMS / clipboard).
  sharePhoneClaimLink(phone) {
    const link = `${this.getAppUrl()}?claimPhone=${encodeURIComponent(phone)}`;
    const message = `I've sent you a voucher on Promise Voucher Network. Sign in with your phone number to claim it: ${link}`;

    const modal = document.createElement('div');
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:1000';
    modal.innerHTML = `
      <div style="background:var(--bg-card,#1e2a3a);border-radius:12px;padding:24px;max-width:400px;width:90%;box-shadow:0 4px 24px rgba(0,0,0,0.4)">
        <h3 style="margin:0 0 12px;color:var(--text-primary,#e2e8f0)">Voucher reserved for ${phone}</h3>
        <p style="margin:0 0 16px;font-size:0.9em;color:var(--text-secondary,#94a3b8)">The app can't text them automatically — share this link so they can claim the voucher by signing in with their phone number.</p>
        <input readonly id="claimLinkField" value="${link}" style="width:100%;margin-bottom:16px;padding:8px;border-radius:6px;border:1px solid var(--border,#334155);background:var(--bg-input,#0f172a);color:var(--text-primary,#e2e8f0);font-size:12px">
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          ${navigator.share ? '<button id="claimShareBtn" class="btn btn--primary" style="flex:1">Share…</button>' : ''}
          <a href="sms:${phone}?&body=${encodeURIComponent(message)}" class="btn btn--secondary" style="flex:1;text-align:center;text-decoration:none">Text them</a>
          <button id="claimCopyBtn" class="btn btn--secondary" style="flex:1">Copy link</button>
        </div>
        <button id="claimCloseBtn" class="btn btn--secondary btn--full-width" style="margin-top:8px">Done</button>
      </div>
    `;
    document.body.appendChild(modal);
    const shareBtn = document.getElementById('claimShareBtn');
    if (shareBtn) {
      shareBtn.onclick = () => {
        navigator.share({ title: 'Promise Voucher', text: message }).catch(() => {});
      };
    }
    document.getElementById('claimCopyBtn').onclick = () => {
      const field = document.getElementById('claimLinkField');
      field.select();
      if (navigator.clipboard) navigator.clipboard.writeText(link).catch(() => {});
      else document.execCommand('copy');
      this.showToast('Link copied', 'success');
    };
    document.getElementById('claimCloseBtn').onclick = () => document.body.removeChild(modal);
  }

  // Runs on every sign-in: establish my phone identity, backfill the users
  // doc so senders can find this account by number, then migrate anything
  // reserved under pending-users/{myPhone}.
  async claimPhonePromises() {
    try {
      const phone = this.currentUser.phoneNumber
        || (this.currentUserDoc && this.currentUserDoc.phoneNumber)
        || null;
      if (!phone) return;
      this.myPhoneNumber = phone;

      if (!this.currentUserDoc || !this.currentUserDoc.phoneNumber) {
        await this.db.collection('users').doc(this.currentUser.uid).update({
          phoneNumber: phone,
          updatedAt: new Date().toISOString()
        });
        if (this.currentUserDoc) this.currentUserDoc.phoneNumber = phone;
      }

      await this.migratePendingPhonePromises(phone);
    } catch (error) {
      console.error('Error claiming phone promises:', error);
    }
  }

  // Migrate promises addressed to a pending phone placeholder onto my real
  // account: decrypt with the placeholder key, re-encrypt for my own key.
  // Migrate, don't adopt — the placeholder keypair dies here, so anyone who
  // saw the pending doc can't read promises sent after the claim.
  async migratePendingPhonePromises(phone) {
    const pendingRef = this.db.collection('pending-users').doc(phone);
    const pendingDoc = await pendingRef.get();
    if (!pendingDoc.exists) return;

    if (!this.myKeyPair || !this.myKeyPair.secretKey) {
      // Keys unavailable on this device — leave the pending doc for a sign-in that has them.
      console.warn('Pending phone promises found but keys not loaded; skipping claim');
      return;
    }

    const pendingSecretKey = nacl.util.decodeBase64(pendingDoc.data().secretKey);
    const myPublicKey = nacl.util.encodeBase64(this.myKeyPair.publicKey);

    const snap = await this.db.collection('promises').where('receiverPhone', '==', phone).get();
    const batch = this.db.batch();
    let claimed = 0;
    let failed = 0;
    snap.docs.forEach(doc => {
      const p = doc.data();
      if (p.receiverId != null) return; // already owned by a real account
      let plain;
      try {
        plain = PromiseEncryption.decrypt(p.contentEncryptedForReceiver, pendingSecretKey);
      } catch (e) {
        console.error('Could not decrypt pending promise', doc.id, e);
        failed++;
        return;
      }
      batch.update(doc.ref, {
        receiverId: this.currentUser.uid,
        receiverEmail: this.currentUser.email || null,
        contentEncryptedForReceiver: PromiseEncryption.encrypt(plain, myPublicKey),
        updatedAt: new Date().toISOString()
      });
      claimed++;
    });
    // Keep the placeholder if anything failed to migrate, so a later sign-in
    // can retry; otherwise it has served its purpose.
    if (failed === 0) batch.delete(pendingRef);
    await batch.commit();
    if (claimed > 0) {
      this.showToast(`${claimed} voucher(s) claimed — they're in your inbox`, 'success');
    }
  }

  // ===== PROMISE STATE HELPERS =====
  // Does this promise belong to me (as sender or current receiver)?
  isMine(promise) {
    return promise.senderId === this.currentUser.uid
      || this.isCurrentReceiver(promise);
  }

  // Past its expiry date and never redeemed
  isExpired(promise) {
    return promise.status !== 'redeemed'
      && !!promise.expiresAt
      && new Date(promise.expiresAt) < new Date();
  }

  // Live promise: neither redeemed, transferred, nor expired (this is what Inbox/Outbox show)
  isActive(promise) {
    return promise.status !== 'redeemed' && promise.status !== 'transferred' && !this.isExpired(promise);
  }

  relativeTime(isoString) {
    const diff = Date.now() - new Date(isoString).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 2) return 'just now';
    if (mins < 60) return `${mins} minutes ago`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    const days = Math.floor(hours / 24);
    if (days === 1) return 'yesterday';
    if (days < 7) return `${days} days ago`;
    return new Date(isoString).toLocaleDateString();
  }

  formatActivityTime(isoString) {
    const d = new Date(isoString);
    const now = new Date();
    const hh = String(d.getHours()).padStart(2, '0');
    const mm = String(d.getMinutes()).padStart(2, '0');
    const sameDay = d.toDateString() === now.toDateString();
    const yesterday = new Date(now); yesterday.setDate(now.getDate() - 1);
    const isYesterday = d.toDateString() === yesterday.toDateString();
    if (sameDay) return `Today ${hh}:${mm}`;
    if (isYesterday) return `Yesterday ${hh}:${mm}`;
    const dd = String(d.getDate()).padStart(2, '0');
    const mo = String(d.getMonth() + 1).padStart(2, '0');
    return `${dd}/${mo} ${hh}:${mm}`;
  }

  formatActivityEntry(entry) {
    const who = this.displayName(entry.by);
    const when = this.formatActivityTime(entry.timestamp);
    const snippet = entry.content ? ` "${entry.content.slice(0, 50)}${entry.content.length > 50 ? '…' : ''}"` : '';
    const ico = (e) => `<span style="display:inline-block;width:1.4em;font-size:1.1em;">${e}</span>`;
    switch (entry.type) {
      case 'created':  return `${ico('🎉')}<strong>${who}</strong> created this pool · <em>${when}</em>`;
      case 'joined':   return `${ico('👋')}<strong>${who}</strong> joined · <em>${when}</em>`;
      case 'left':     return `${ico('🚪')}<strong>${who}</strong> left · <em>${when}</em>`;
      case 'posted': {
        const qty = entry.quantity > 1 ? ` (×${entry.quantity})` : '';
        return `${ico('📝')}<strong>${who}</strong> posted${snippet}${qty} · <em>${when}</em>`;
      }
      case 'invited':  return `${ico('📨')}<strong>${who}</strong> invited ${this.displayName(entry.invitee || '')} · <em>${when}</em>`;
      case 'redeemed': return `${ico('✅')}<strong>${who}</strong> redeemed${snippet} · <em>${when}</em>`;
      case 'transferred': {
        const to = entry.to ? ` → ${this.displayName(entry.to)}` : '';
        const plane = `<img src="paper-airplane.png" alt="" style="width:1.2em;height:1.2em;vertical-align:-3px;margin-right:4px;">`;
        return `<span style="display:inline-block;width:1.6em;">${plane}</span><strong>${who}</strong> transferred${snippet}${to} · <em>${when}</em>`;
      }
      case 'trusted-pool-added': {
        const tname = entry.trustedPoolName || entry.trustedPoolId || '';
        return `${ico('🤝')}<strong>${who}</strong> added trusted pool "${tname}" · <em>${when}</em>`;
      }
      case 'trusted-pool-removed':
        return `${ico('✂️')}<strong>${who}</strong> removed trusted pool "${entry.trustedPoolId || ''}" · <em>${when}</em>`;
      case 'transferred-to-pool': {
        const dest = (this.myPools.get(entry.toPoolId) || {}).name || entry.toPoolId || '';
        return `${ico('🤝')}<strong>${who}</strong> transferred${snippet} to pool "${dest}" · <em>${when}</em>`;
      }
      case 'received-from-pool': {
        const src = (this.myPools.get(entry.fromPoolId) || {}).name || entry.fromPoolId || '';
        return `${ico('📥')}<strong>${who}</strong> brought${snippet} from pool "${src}" · <em>${when}</em>`;
      }
      default: return `${ico('📋')}<strong>${who}</strong> ${entry.type}${snippet} · <em>${when}</em>`;
    }
  }

  async loadPoolActivity(poolId) {
    const panel = document.getElementById(`pool-tab-activity-${poolId}`);
    if (!panel) return;
    panel.innerHTML = '<p style="color:var(--color-text-secondary);padding:12px">Loading activity…</p>';
    try {
      const snap = await this.db.collection('pools').doc(poolId).collection('activity')
        .orderBy('timestamp', 'desc').limit(50).get();
      if (snap.empty) {
        panel.innerHTML = '<p style="color:var(--color-text-secondary);padding:12px">No activity yet.</p>';
        return;
      }
      panel.innerHTML = snap.docs.map(doc => {
        const entry = doc.data();
        return `<div style="padding:10px 0;border-bottom:1px solid var(--color-border);font-size:14px;line-height:1.5">${this.formatActivityEntry(entry)}</div>`;
      }).join('');
    } catch (e) {
      panel.innerHTML = '<p style="color:var(--color-text-secondary);padding:12px">Could not load activity.</p>';
    }
  }

  switchPoolTab(poolId, tab) {
    const promisesPanel = document.getElementById(`pool-tab-promises-${poolId}`);
    const activityPanel = document.getElementById(`pool-tab-activity-${poolId}`);
    const promisesBtn = document.getElementById(`pool-tabbtn-promises-${poolId}`);
    const activityBtn = document.getElementById(`pool-tabbtn-activity-${poolId}`);
    if (!promisesPanel || !activityPanel) return;
    const activeStyle = 'border-bottom:2px solid var(--color-primary,#6366f1);color:var(--color-primary,#6366f1);font-weight:600;';
    const inactiveStyle = 'border-bottom:2px solid transparent;color:var(--color-text-secondary);font-weight:400;';
    if (tab === 'promises') {
      promisesPanel.style.display = '';
      activityPanel.style.display = 'none';
      if (promisesBtn) promisesBtn.style.cssText += activeStyle;
      if (activityBtn) activityBtn.style.cssText += inactiveStyle;
    } else {
      promisesPanel.style.display = 'none';
      activityPanel.style.display = '';
      if (promisesBtn) promisesBtn.style.cssText += inactiveStyle;
      if (activityBtn) activityBtn.style.cssText += activeStyle;
      if (!activityPanel.dataset.loaded) {
        activityPanel.dataset.loaded = '1';
        this.loadPoolActivity(poolId);
      }
    }
  }

  addActivity(message) {
    const timestamp = new Date().toLocaleString();
    this.activities.push(`${timestamp}: ${message}`);
    this.updateDashboard();
  }

  showToast(message, type = 'info') {
    console.log(`${type.toUpperCase()}: ${message}`);
    // You can enhance this with a proper toast UI later
    alert(message);
  }

showLoading() {
  const overlay = document.getElementById('loadingOverlay');
  if (overlay) overlay.style.display = 'flex';  // Show it
}

hideLoading() {
  const overlay = document.getElementById('loadingOverlay');
  if (overlay) overlay.style.display = 'none';  // Hide it
}
}

// ===== INITIALIZE APP =====
let app;
document.addEventListener('DOMContentLoaded', () => {
  try {
    app = new FirebasePromiseApp();
  } catch (error) {
    console.error('Failed to initialize app:', error);
  }
});

// ===== R1 VOICE BRIDGE =====
// Receives voice transcripts from the wrapper Creation via postMessage
// and fills in the active text input or opens the create promise modal
window.addEventListener('message', (e) => {
  if (!e.data || e.data.type !== 'r1-voice-transcript') return;
  const text = e.data.text;
  if (!text) return;

  // Find the focused input first, otherwise target the promise description field
  const focused = document.activeElement;
  if (focused && (focused.tagName === 'INPUT' || focused.tagName === 'TEXTAREA') && focused.id !== 'searchInput') {
    focused.value = focused.value + text;
    focused.dispatchEvent(new Event('input', { bubbles: true }));
    return;
  }

  // If create modal is open, fill in description
  const descField = document.getElementById('promiseDescription') || document.getElementById('newPromiseText');
  if (descField && descField.closest('.modal')?.style.display !== 'none') {
    descField.value = descField.value + text;
    descField.dispatchEvent(new Event('input', { bubbles: true }));
    return;
  }

  // Otherwise open the FAB modal and fill it
  const fab = document.getElementById('createPromiseFAB');
  if (fab) {
    fab.click();
    setTimeout(() => {
      const field = document.getElementById('promiseDescription') || document.getElementById('newPromiseText');
      if (field) {
        field.value = text;
        field.dispatchEvent(new Event('input', { bubbles: true }));
      }
    }, 300);
  }
});

// ===== R1 ON-SCREEN KEYBOARD + ORIENTATION =====
// Only active inside the R1 Creation (html.r1-mode). Provides a DOM keyboard
// (native R1 keyboard is unreliable / breaks landscape) and responds to
// orientation messages posted by the wrapper's accelerometer.
(function () {
  if (!document.documentElement.classList.contains('r1-mode')) return;

  /* ---------- Orientation (driven by the wrapper's accelerometer) ---------- */
  const viewportMeta = document.getElementById('viewportMeta');
  window.addEventListener('message', (e) => {
    if (!e.data || e.data.type !== 'r1-orientation') return;
    const landscape = !!e.data.landscape;
    document.body.classList.toggle('landscape', landscape);
    if (viewportMeta) {
      viewportMeta.setAttribute('content',
        'width=' + (landscape ? 282 : 240) + ', initial-scale=1.0, user-scalable=no');
    }
  });

  /* ---------- DOM keyboard ---------- */
  const letters = [
    ['q','w','e','r','t','y','u','i','o','p'],
    ['a','s','d','f','g','h','j','k','l'],
    ['z','x','c','v','b','n','m']
  ];
  const symbols = [
    ['1','2','3','4','5','6','7','8','9','0'],
    ['-','/',':',';','(',')','$','&','@','"'],
    ['.',',','?','!','\'']
  ];
  let shifted = false, symMode = false, targetEl = null;

  const kb = document.createElement('div');
  kb.id = 'r1-keyboard';
  document.body.appendChild(kb);

  function build() {
    const src = symMode ? symbols : letters;
    let html = '';
    src.forEach((row, i) => {
      html += '<div class="r1kb-row">';
      if (i === 2) html += '<button class="r1kb-key wide" data-act="shift">' + (symMode ? '.,?' : '⇧') + '</button>';
      row.forEach(k => {
        const label = (!symMode && shifted) ? k.toUpperCase() : k;
        html += '<button class="r1kb-key" data-k="' + k.replace(/"/g, '&quot;') + '">' + label.replace(/"/g, '&quot;') + '</button>';
      });
      if (i === 2) html += '<button class="r1kb-key wide" data-act="back">⌫</button>';
      html += '</div>';
    });
    html += '<div class="r1kb-row">'
      + '<button class="r1kb-key wide" data-act="sym">' + (symMode ? 'abc' : '?123') + '</button>'
      + '<button class="r1kb-key space" data-act="space">space</button>'
      + '<button class="r1kb-key wide action" data-act="enter">↵</button>'
      + '<button class="r1kb-key wide" data-act="hide">▼</button>'
      + '</div>';
    kb.innerHTML = html;
  }
  build();

  const NON_TEXT_INPUT = /^(checkbox|radio|range|file|color|button|submit|reset|image|hidden)$/i;
  function isEditable(el) {
    if (!el) return false;
    if (el.tagName === 'TEXTAREA') return true;
    if (el.tagName === 'INPUT') return !NON_TEXT_INPUT.test(el.type || 'text');
    return false;
  }
  function current() { const el = targetEl || document.activeElement; return isEditable(el) ? el : null; }
  function fireInput(el) { el.dispatchEvent(new Event('input', { bubbles: true })); }

  function typeChar(ch) {
    const el = current(); if (!el) return;
    const s = el.selectionStart ?? el.value.length;
    const e = el.selectionEnd ?? s;
    el.value = el.value.slice(0, s) + ch + el.value.slice(e);
    el.selectionStart = el.selectionEnd = s + ch.length;
    fireInput(el);
  }
  function backspace() {
    const el = current(); if (!el) return;
    const s = el.selectionStart ?? el.value.length;
    const e = el.selectionEnd ?? s;
    if (s !== e) { el.value = el.value.slice(0, s) + el.value.slice(e); el.selectionStart = el.selectionEnd = s; }
    else if (s > 0) { el.value = el.value.slice(0, s - 1) + el.value.slice(s); el.selectionStart = el.selectionEnd = s - 1; }
    fireInput(el);
  }
  function showKb() { document.body.classList.add('r1kb-open'); }
  function hideKb() { document.body.classList.remove('r1kb-open'); }

  function handleKey(e) {
    const key = e.target.closest('.r1kb-key'); if (!key) return;
    e.preventDefault();
    const act = key.dataset.act, k = key.dataset.k;
    if (k != null) {
      typeChar((!symMode && shifted) ? k.toUpperCase() : k);
      if (shifted) { shifted = false; build(); }
      return;
    }
    switch (act) {
      case 'shift': shifted = !shifted; build(); break;
      case 'sym': symMode = !symMode; shifted = false; build(); break;
      case 'back': backspace(); break;
      case 'space': typeChar(' '); break;
      case 'enter': {
        const el = current();
        if (el && el.tagName === 'TEXTAREA') typeChar('\n');
        else { hideKb(); if (el) el.blur(); }
        break;
      }
      case 'hide': { const el = current(); hideKb(); if (el) el.blur(); break; }
    }
  }

  kb.addEventListener('mousedown', e => e.preventDefault()); // don't steal focus
  kb.addEventListener('touchstart', (e) => {
    const key = e.target.closest('.r1kb-key');
    if (key) { e.preventDefault(); key.classList.add('pressed'); setTimeout(() => key.classList.remove('pressed'), 120); }
  }, { passive: false });
  kb.addEventListener('touchend', handleKey); // primary (R1 touch)
  kb.addEventListener('click', handleKey);    // fallback (desktop)

  // Suppress the native keyboard on every editable field. inputmode="none" is
  // NOT respected by the R1 WebView, so the reliable lever is `readonly`: it
  // blocks the native keyboard on tap while still allowing programmatic value +
  // selection changes (which is how our DOM keyboard writes into the field).
  // Must be applied before the field is focused.
  function suppressNative(el) {
    if (!isEditable(el)) return;
    if (!el.hasAttribute('readonly')) {
      el.setAttribute('readonly', '');
      el.dataset.r1kbReadonly = '1'; // mark ours, so we don't fight app-set readonly
    }
    if (el.getAttribute('inputmode') !== 'none') el.setAttribute('inputmode', 'none');
    el.setAttribute('autocomplete', 'off');
    el.setAttribute('spellcheck', 'false');
  }
  document.querySelectorAll('input, textarea').forEach(suppressNative);
  new MutationObserver((muts) => {
    muts.forEach(m => m.addedNodes && m.addedNodes.forEach(n => {
      if (n.nodeType !== 1) return;
      if (isEditable(n)) suppressNative(n);
      if (n.querySelectorAll) n.querySelectorAll('input, textarea').forEach(suppressNative);
    }));
  }).observe(document.body, { childList: true, subtree: true });

  function openFor(el) {
    if (!isEditable(el)) return;
    targetEl = el;
    suppressNative(el);
    try { el.focus(); } catch (_) {}
    showKb();
    setTimeout(() => { try { el.scrollIntoView({ block: 'center' }); } catch (_) {} }, 60);
  }
  document.addEventListener('focusin', (e) => { if (isEditable(e.target)) openFor(e.target); });
  // Tap fallback — readonly inputs may not always emit focusin on R1.
  document.addEventListener('touchend', (e) => {
    const el = e.target.closest && e.target.closest('input, textarea');
    if (el && isEditable(el)) openFor(el);
  });
  document.addEventListener('click', (e) => {
    const el = e.target.closest && e.target.closest('input, textarea');
    if (el && isEditable(el)) openFor(el);
  });
  document.addEventListener('focusout', () => {
    setTimeout(() => { if (!isEditable(document.activeElement)) hideKb(); }, 150);
  });
})();
