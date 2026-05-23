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
    this.activities = [];

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
      await this.auth.signInWithEmailAndPassword(email, password);
      // onAuthStateChanged will handle the rest
    } catch (error) {
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

    // ← ADD THIS BLOCK: If not found locally, try to recover from Firestore with password
    if (!storedSecretKey && doc.data().encryptedSecretKey) {
      console.log('Secret key not in local storage, attempting recovery from Firestore...');
      const password = prompt('Enter your password to decrypt messages on this device:');
      if (password) {
        try {
          storedSecretKey = await this.recoverSecretKeyFromPassword(password);
          this.storeSecretKeyLocally(storedSecretKey); // Save for next time
          console.log('Secret key recovered from password');
        } catch (error) {
          console.error('Failed to recover key:', error);
          alert('Could not recover encryption key. Wrong password?');
        }
      } else {
        console.log('User cancelled password prompt');
      }
    }

    // If not in localStorage, try fetching from Firestore (login = key access)
    if (!storedSecretKey && doc.data().secretKey) {
      storedSecretKey = doc.data().secretKey;
      this.storeSecretKeyLocally(storedSecretKey);
      console.log('Secret key loaded from Firestore');
    }

    if (storedSecretKey) {
      this.myKeyPair = {
        publicKey: nacl.util.decodeBase64(doc.data().publicKey),
        secretKey: nacl.util.decodeBase64(storedSecretKey)
      };
      // Backfill: if key was only local, save it to Firestore for cross-device access
      if (!doc.data().secretKey) {
        await userDocRef.update({ secretKey: storedSecretKey, updatedAt: new Date().toISOString() });
      }
    } else {
      // No key found anywhere — generate a new one for this device/login.
      // Existing promises encrypted with the old key won't decrypt until the user
      // opens the app on their original device (which will backfill the key to Firestore).
      console.warn('No secret key found — generating new key pair.');
      this.myKeyPair = PromiseEncryption.generateKeyPair();
      const newPublicKey = nacl.util.encodeBase64(this.myKeyPair.publicKey);
      const newSecretKey = nacl.util.encodeBase64(this.myKeyPair.secretKey);
      await userDocRef.update({ publicKey: newPublicKey, secretKey: newSecretKey, updatedAt: new Date().toISOString() });
      this.storeSecretKeyLocally(newSecretKey);
      if (this.currentUserDoc) this.currentUserDoc.publicKey = newPublicKey;
      this.showToast('New device: open the app on your original device to restore old promises', 'info');
    }
    console.log('Encryption keys loaded');
    } catch (error) {
    console.error('Error loading encryption keys:', error);
    } finally {
    this.keysLoading = false;
    }
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
            } else if (promise.receiverEmail === this.currentUser.email) {
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

    // Listen to my contacts
    console.log('Attaching contacts listener...');
    const contactsUnsub = this.db.collection('users')
      .doc(this.currentUser.uid)
      .collection('contacts')
      .onSnapshot(async (snapshot) => {
        console.log('Contacts snapshot received:', snapshot.size);
        this.contacts.clear();
        snapshot.forEach((doc) => {
          this.contacts.set(doc.data().email, doc.data());
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
      const receiverEmail = document.getElementById('promiseReceiver').value.trim()
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
          this.showToast(`Posted to pool "${poolTemplate.poolName}"`, 'success');
          this.addActivity(`Posted ${quantity} promise(s) to pool "${poolTemplate.poolName}"`);
          document.getElementById('createPromiseForm').reset();
          this.selectedPoolId = null;
          const ri = document.getElementById('promiseReceiver');
          if (ri) {
            ri.disabled = false;
            ri.placeholder = 'Type an email, or pick a contact below...';
          }
        } catch (error) {
          console.error('Pool promise error:', error);
          this.showToast('Failed to post pool promise', 'error');
        } finally {
          this.hideLoading();
        }
        return;
      }

      if (!receiverEmail) {
        this.showToast('Please fill in all required fields', 'error');
        return;
      }

      if (!this.isValidEmail(receiverEmail)) {
        this.showToast('Please enter a valid email address for the recipient', 'error');
        return;
      }

      this.showLoading();
      try {
        // Check if receiver exists
        const userQuery = await this.db.collection('users')
          .where('email', '==', receiverEmail)
          .get();

        if (userQuery.empty) {
          this.showToast('Receiver not found', 'error');
          this.hideLoading();
          return;
        }

        const receiverId = userQuery.docs[0].id;

        // If the recipient was typed in (not an existing contact), add them to the
        // Network automatically so the user can grow their contacts from this screen.
        if (!this.contacts.has(receiverEmail)) {
          try {
            await this.db.collection('users')
              .doc(this.currentUser.uid)
              .collection('contacts')
              .doc(receiverId)
              .set({
                email: receiverEmail,
                addedAt: new Date().toISOString()
              });
            this.addActivity(`Contact "${receiverEmail}" added`);
          } catch (e) {
            // Non-fatal — sending the promise still proceeds
            console.error('Failed to auto-add contact:', e);
          }
        }

        // Fetch receiver's public key
        const receiverUserDoc = await this.db.collection('users').doc(receiverId).get();
        const receiverPublicKey = receiverUserDoc.data().publicKey;

        // ✅ Encrypt for receiver (only they can read it)
        const encryptedForReceiver = PromiseEncryption.encrypt(content, receiverPublicKey);
        // ✅ Encrypt for sender (archive - sender can read from any device)
        const encryptedForSender = PromiseEncryption.encrypt(content, this.currentUserDoc.publicKey);

        // ✅ BUILD THE PROMISE TEMPLATE (same for all copies)
        const promiseTemplate = {
          contentEncryptedForReceiver: encryptedForReceiver,
          contentEncryptedForSender: encryptedForSender,
          senderId: this.currentUser.uid,
          senderEmail: this.currentUser.email,
          receiverId: receiverId,
          receiverEmail: receiverEmail,
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
          this.addActivity(`Promise created for ${receiverEmail}: "[encrypted]"`);
        } else {
          // Batch create multiple promises
          const batch = this.db.batch();
          for (let i = 0; i < quantity; i++) {
            const docRef = this.db.collection('promises').doc();
            batch.set(docRef, promiseTemplate);
          }
          await batch.commit();
          this.showToast(`${quantity} promises created successfully`, 'success');
          this.addActivity(`Batch created ${quantity} promises for ${receiverEmail}`);
        }

        document.getElementById('createPromiseForm').reset();
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
        const newReceiverEmail = document.getElementById('transferReceiver').value;

        if (!promiseId || !newReceiverEmail) {
            this.showToast('Please select a promise and new receiver', 'error');
            return;
        }

        // Route to pool transfer if a pool was selected
        if (newReceiverEmail.startsWith('pool:')) {
            const poolId = newReceiverEmail.slice(5);
            document.getElementById('transferPromiseForm').reset();
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
        if (promise.receiverEmail !== this.currentUser.email) {
            this.showToast('Only the current receiver can transfer this promise', 'error');
            return;
        }

        this.showLoading();

        try {
            // Look up new receiver
            const userQuery = await this.db.collection('users')
                .where('email', '==', newReceiverEmail)
                .get();

            if (userQuery.empty) {
                this.showToast('New receiver not found', 'error');
                this.hideLoading();
                return;
            }

            const newReceiverId = userQuery.docs[0].id;
            const newReceiverDoc = userQuery.docs[0].data();
            const newReceiverPublicKey = newReceiverDoc.publicKey;

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
                receiverId: newReceiverId,
                receiverEmail: newReceiverEmail,
                contentEncryptedForReceiver: newEncryptedForReceiver,
                updatedAt: new Date().toISOString(),
                transferHistory: firebase.firestore.FieldValue.arrayUnion({
                    from: promise.receiverEmail,
                    to: newReceiverEmail,
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
            this.addActivity(`Promise transferred to ${newReceiverEmail}`);
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

  toggleSettings() {
    const panel = document.getElementById('settingsPanel');
    if (!panel) return;
    const isHidden = panel.style.display === 'none' || panel.style.display === '';
    panel.style.display = isHidden ? 'block' : 'none';
    if (isHidden) {
      const input = document.getElementById('usernameInput');
      if (input && this.currentUsername) input.value = this.currentUsername;
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
    if (promise.receiverEmail !== this.currentUser.email) {
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

  showPoolTransferUI(promiseId) {
    const promise = this.promises.get(promiseId);
    if (!promise) return;
    const contacts = Array.from(this.contacts.values());
    if (contacts.length === 0) {
      this.showToast('Add contacts first to transfer a promise', 'error');
      return;
    }
    const contactOptions = contacts.map(c => {
      const name = this.usernames.get(c.email) ? `@${this.usernames.get(c.email)} (${c.email})` : c.email;
      return `<option value="${c.email}">${name}</option>`;
    }).join('');

    const modal = document.createElement('div');
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:1000';
    modal.innerHTML = `
      <div style="background:var(--bg-card,#1e2a3a);border-radius:12px;padding:24px;max-width:400px;width:90%;box-shadow:0 4px 24px rgba(0,0,0,0.4)">
        <h3 style="margin:0 0 12px;color:var(--text-primary,#e2e8f0)">Transfer as Payment</h3>
        <p style="margin:0 0 16px;font-size:0.9em;color:var(--text-secondary,#94a3b8)">"${promise.content}"</p>
        <select id="poolTransferRecipient" style="width:100%;margin-bottom:16px;padding:8px;border-radius:6px;border:1px solid var(--border,#334155);background:var(--bg-input,#0f172a);color:var(--text-primary,#e2e8f0)">
          <option value="">-- Select recipient --</option>
          ${contactOptions}
        </select>
        <div style="display:flex;gap:8px">
          <button id="confirmPoolTransfer" class="btn btn--primary" style="flex:1">Transfer</button>
          <button id="cancelPoolTransfer" class="btn btn--secondary" style="flex:1">Cancel</button>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
    document.getElementById('confirmPoolTransfer').onclick = async () => {
      const recipientEmail = document.getElementById('poolTransferRecipient').value;
      if (!recipientEmail) { this.showToast('Select a recipient', 'error'); return; }
      document.body.removeChild(modal);
      await this.transferPoolPromise(promiseId, recipientEmail);
    };
    document.getElementById('cancelPoolTransfer').onclick = () => document.body.removeChild(modal);
  }

  async transferPoolPromise(promiseId, recipientEmail) {
    const promise = this.promises.get(promiseId);
    if (!promise || !promise.isPoolPromise) { this.showToast('Promise not found', 'error'); return; }
    if (!this.myKeyPair) { this.showToast('Encryption keys not loaded', 'error'); return; }
    this.showLoading();
    try {
      const userQuery = await this.db.collection('users').where('email', '==', recipientEmail).get();
      if (userQuery.empty) { this.showToast('Recipient not found', 'error'); this.hideLoading(); return; }
      const recipientDoc = userQuery.docs[0];
      const recipientPublicKey = recipientDoc.data().publicKey;
      const now = new Date().toISOString();

      const encryptedForRecipient = PromiseEncryption.encrypt(promise.content, recipientPublicKey);
      const encryptedForSender = PromiseEncryption.encrypt(promise.content, this.currentUserDoc.publicKey);

      const batch = this.db.batch();
      batch.set(this.db.collection('promises').doc(), {
        senderId: this.currentUser.uid,
        senderEmail: this.currentUser.email,
        receiverId: recipientDoc.id,
        receiverEmail: recipientEmail,
        contentEncryptedForReceiver: encryptedForRecipient,
        contentEncryptedForSender: encryptedForSender,
        status: 'active',
        locked: false,
        createdAt: now,
        transferHistory: [{ from: `pool:${promise.poolId}`, to: recipientEmail, timestamp: now }],
      });
      batch.update(this.db.collection('promises').doc(promiseId), {
        status: 'transferred',
        transferredBy: this.currentUser.email,
        transferredTo: recipientEmail,
        updatedAt: now,
      });
      batch.set(this.db.collection('pools').doc(promise.poolId).collection('activity').doc(), {
        type: 'transferred',
        promiseId,
        content: promise.content,
        by: this.currentUser.email,
        to: recipientEmail,
        timestamp: now,
      });
      await batch.commit();
      this.showToast(`Promise transferred to ${this.displayName(recipientEmail)}`, 'success');
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

    if (promise.receiverEmail !== this.currentUser.email) {
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
        const email = document.getElementById('contactName').value.trim();

        if (!email || !this.isValidEmail(email)) {
            this.showToast('Please enter a valid email', 'error');
            return;
        }

        // Check if email exists in users collection
        const userQuery = await this.db.collection('users')
            .where('email', '==', email)
            .get();

        if (userQuery.empty) {
            this.showToast('User not found', 'error');
            return;
        }

        try {
            const contactUserId = userQuery.docs[0].id;

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
                    email: email,
                    addedAt: new Date().toISOString()
                });

            document.getElementById('addContactForm').reset();

            // ✅ Better message for self-contact
            if (email === this.currentUser.email) {
                this.showToast('Added yourself as contact (for self-promises)', 'success');
            } else {
                this.showToast('Contact added successfully', 'success');
            }

            this.addActivity(`Contact "${email}" added`);

        } catch (error) {
            this.showToast('Failed to add contact', 'error');
            console.error('Error:', error);
        }
    }


  async removeContact(email) {
    try {
      const userQuery = await this.db.collection('users')
        .where('email', '==', email)
        .get();

      if (!userQuery.empty) {
        await this.db.collection('users')
          .doc(this.currentUser.uid)
          .collection('contacts')
          .doc(userQuery.docs[0].id)
          .delete();

        this.showToast('Contact removed successfully', 'success');
        this.addActivity(`Contact "${email}" removed`);
      }
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
                            receiverInput.placeholder = 'Type an email, or pick a contact below...';
                        }
                        return;
                    }
                    if (val.startsWith('pool:')) {
                        this.selectedPoolId = val.slice(5);
                        const pool = this.myPools.get(this.selectedPoolId);
                        if (receiverInput) {
                            receiverInput.value = '';
                            receiverInput.disabled = true;
                            receiverInput.placeholder = `📢 Posting to pool "${pool ? pool.name : this.selectedPoolId}" (public)`;
                        }
                    } else {
                        this.selectedPoolId = null;
                        if (receiverInput) {
                            receiverInput.disabled = false;
                            receiverInput.value = val;
                            receiverInput.placeholder = 'Type an email, or pick a contact below...';
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
                                <strong>Current Receiver:</strong> ${promise.receiverEmail}
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
          .filter(p => p.receiverEmail === this.currentUser.email && p.status !== 'redeemed' && p.status !== 'transferred' && !p.locked)
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
              const option = document.createElement('option');
              option.value = contact.email;
              option.textContent = this.usernames.get(contact.email) ? `@${this.usernames.get(contact.email)} (${contact.email})` : contact.email;
              transferReceiver.appendChild(option);
            });

          if (this.myPools.size > 0) {
            const group = document.createElement('optgroup');
            group.label = 'My Pools';
            Array.from(this.myPools.values()).forEach(pool => {
              const option = document.createElement('option');
              option.value = `pool:${pool.poolId}`;
              option.textContent = `📢 ${pool.name || pool.poolId}`;
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
            .filter(p => p.receiverEmail === this.currentUser.email && this.isActive(p))
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
        .filter(p => p.receiverEmail === this.currentUser.email && this.isActive(p))
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
        .map(p => this.renderPromiseCard(p, p.receiverEmail === this.currentUser.email))
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
        .map(p => this.renderPromiseCard(p, p.receiverEmail === this.currentUser.email))
        .join('');
    }

    renderPromiseCard(promise, isInbox) {
      const content = this.decryptPromiseContent(promise);
      const expired = this.isExpired(promise);
      const statusClass = promise.status === 'redeemed' ? 'redeemed' : (expired ? 'expired' : (promise.locked ? 'locked' : ''));
      const statusText = promise.status === 'redeemed' ? '✅ Redeemed' : (expired ? '⏰ Expired' : (promise.locked ? '🔒 Locked' : '✨ Active'));

      const isReceiver = promise.receiverEmail === this.currentUser.email;
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
            <div><strong>${isInbox ? 'From' : 'To'}:</strong> ${this.displayName(isInbox ? promise.senderEmail : promise.receiverEmail)}</div>
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
      const pools = Array.from(this.myPools.values());
      if (pools.length === 0) {
        container.innerHTML = `
          <div class="empty-state">
            <p>📢 You haven't joined any pools yet</p>
            <small>Join a pool above to see public promises from its members</small>
          </div>
        `;
        return;
      }
      container.innerHTML = pools.map(pool => {
        const poolPromises = Array.from(this.promises.values())
          .filter(p => p.poolId === pool.id && this.isActive(p))
          .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        const cards = poolPromises.length === 0
          ? `<div class="empty-state"><p>No active promises in this pool yet</p></div>`
          : poolPromises.map(p => this.renderPoolPromiseCard(p)).join('');
        return `
          <div class="pool-section" style="margin-bottom: var(--space-24);">
            <div class="pool-header" style="display:flex;justify-content:space-between;align-items:center;padding:var(--space-12);background:var(--color-surface);border-radius:8px 8px 0 0;border:1px solid var(--color-border);border-bottom:none;">
              <div>
                <strong>📢 ${pool.name}</strong>
                <div style="font-size:12px;color:var(--color-text-secondary);">id: ${pool.id} · ${poolPromises.length} active</div>
              </div>
              <button onclick="app.leavePool('${pool.id}')" class="btn btn--sm btn--secondary">Leave</button>
            </div>
            <div style="display:flex;gap:8px;padding:8px var(--space-12);background:var(--color-surface);border:1px solid var(--color-border);border-top:none;border-bottom:none;">
              <input type="email" id="inviteInput-${pool.id}" placeholder="Invite by email" class="form-control" style="flex:1;font-size:13px;">
              <button onclick="app.inviteToPool('${pool.id}', '${pool.name.replace(/'/g, "\\'")}', document.getElementById('inviteInput-${pool.id}').value.trim()); document.getElementById('inviteInput-${pool.id}').value='';" class="btn btn--sm btn--primary">Invite</button>
            </div>
            <div class="pool-promises" style="padding-top:var(--space-12);border:1px solid var(--color-border);border-top:none;border-radius:0 0 8px 8px;padding:var(--space-12);">${cards}</div>
          </div>
        `;
      }).join('');
    }

    renderPoolPromiseCard(promise) {
      const content = promise.content || '[No content]';
      const expired = this.isExpired(promise);
      const isActive = promise.status === 'active' && !expired;
      const statusClass = promise.status === 'redeemed' ? 'redeemed' : (promise.status === 'transferred' ? 'redeemed' : (expired ? 'expired' : 'pool'));
      const statusText = promise.status === 'redeemed' ? `✅ Redeemed by ${this.displayName(promise.redeemedBy || '')}` : (promise.status === 'transferred' ? `↗️ Transferred by ${this.displayName(promise.transferredBy || '')}` : (expired ? '⏰ Expired' : '📢 Pool'));
      const createdDate = new Date(promise.createdAt).toLocaleDateString();
      return `
        <div class="promise-card">
          <div class="promise-header">
            <span class="promise-status ${statusClass}">${statusText}</span>
          </div>
          <div class="promise-content">${content}</div>
          <div class="promise-meta">
            <div><strong>From:</strong> ${this.displayName(promise.senderEmail)}</div>
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
          const username = this.usernames.get(contact.email);
          return `
            <div class="contact-card">
              <div class="contact-info">
                ${username ? `<div style="font-weight:600;margin-bottom:2px;">@${username}</div>` : ''}
                <div class="contact-email">${contact.email}</div>
                <div style="font-size: 12px; color: var(--color-text-secondary);">Added ${new Date(contact.addedAt).toLocaleDateString()}</div>
              </div>
              <div class="contact-actions">
                <button onclick="app.removeContact('${contact.email}')" class="btn btn--sm btn--secondary">Remove</button>
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
          .filter(p => p.receiverEmail === this.currentUser.email && this.isActive(p))
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
      .filter(p => p.receiverEmail === this.currentUser.email);

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
        .map(contact => `<option value="${contact.email}"></option>`)
        .join('');
    }

    const select = document.getElementById('promiseReceiverSelect');
    if (select) {
      const pools = Array.from(this.myPools.values());
      let html = '<option value="">— or choose an existing contact or pool —</option>';
      if (contacts.length > 0) {
        html += '<optgroup label="Contacts">' +
          contacts.map(c => {
            const name = this.usernames.get(c.email) ? `@${this.usernames.get(c.email)} (${c.email})` : c.email;
            return `<option value="${c.email}">${name}</option>`;
          }).join('') +
          '</optgroup>';
      }
      if (pools.length > 0) {
        html += '<optgroup label="Pools">' +
          pools.map(p => `<option value="pool:${p.id}">📢 ${p.name}</option>`).join('') +
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

  // ===== PROMISE STATE HELPERS =====
  // Does this promise belong to me (as sender or current receiver)?
  isMine(promise) {
    return promise.senderId === this.currentUser.uid
      || promise.receiverEmail === this.currentUser.email;
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
