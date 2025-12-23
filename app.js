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
    this.activities = [];

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
            await this.loadUserProfile(); // This now handles loadEncryptionKeys internally
            this.showApp();
            this.setupRealtimeListeners();
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

    async signup() {
    console.log('=== SIGNUP CALLED ===');
    const email = document.getElementById('signupEmail').value;
    const password = document.getElementById('signupPassword').value;

    if (password.length < 6) {
    document.getElementById('signupError').textContent = 'Password must be at least 6 characters';
    return;
    }

    try {
    console.log('Creating user with Firebase Auth...');
    const userCred = await this.auth.createUserWithEmailAndPassword(email, password);
    console.log('User created:', userCred.user.uid);

    // Generate encryption keypair
    this.myKeyPair = PromiseEncryption.generateKeyPair();
    const publicKeyBase64 = nacl.util.encodeBase64(this.myKeyPair.publicKey);
    const secretKeyBase64 = nacl.util.encodeBase64(this.myKeyPair.secretKey);

    console.log('Creating Firestore user doc with public key...');
    await this.db.collection('users').doc(userCred.user.uid).set({
      email: email,
      publicKey: publicKeyBase64,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    });

    // Store secret key in browser
    this.storeSecretKeyLocally(secretKeyBase64);

    // ← ADD THESE LINES: Store encrypted secret key in Firestore for recovery
    console.log('Storing encrypted secret key in Firestore...');
    await this.encryptAndStoreSecretKey(secretKeyBase64, password);

    console.log('User doc created successfully');
    // onAuthStateChanged will handle the rest
    } catch (error) {
    console.error('SIGNUP ERROR:', error);
    document.getElementById('signupError').textContent = error.message;
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

    if (storedSecretKey) {
      this.myKeyPair = {
        publicKey: nacl.util.decodeBase64(doc.data().publicKey),
        secretKey: nacl.util.decodeBase64(storedSecretKey)
      };
    } else {
      console.warn('Secret key not found. User should log in on original device or enter password.');
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
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
          });

          this.storeSecretKeyLocally(secretKeyBase64);
          this.currentUserDoc = (await userDocRef.get()).data();
        }
        // Load encryption keys
        await this.loadEncryptionKeys();
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
      .onSnapshot((snapshot) => {
        console.log('Contacts snapshot received:', snapshot.size);
        this.contacts.clear();
        snapshot.forEach((doc) => {
          this.contacts.set(doc.data().email, doc.data());
        });
        this.updateUI();
      });
    this.unsubscribers.push(contactsUnsub);

    console.log('All listeners attached');
  }

  // ===== PROMISE OPERATIONS =====
      async createPromise() {
      const content = document.getElementById('promiseContent').value.trim();
      const receiverEmail = document.getElementById('promiseReceiver').value;
      const expiration = document.getElementById('promiseExpiration').value;
      const locked = document.getElementById('promiseLock').checked;
      const quantity = parseInt(document.getElementById('promiseQuantity').value) || 1;

      if (!content || !receiverEmail) {
        this.showToast('Please fill in all required fields', 'error');
        return;
      }

      if (quantity < 1 || quantity > 1000) {
        this.showToast('Quantity must be between 1 and 1000', 'error');
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



  showTransferUI(promiseId) {
    console.log('Showing transfer UI for promise:', promiseId);
    // Set the promise select to this promise
    document.getElementById('transferPromiseSelect').value = promiseId;
    // Switch to transfer tab
    this.switchTab('transfer');
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
  document.getElementById('currentAgentKey').textContent = this.currentUser.email;

  // ✅ Setup app listeners ONCE
  if (!this.eventListenersInitialized) {
    console.log('Calling setupEventListeners...');
    this.setupEventListeners();
    this.eventListenersInitialized = true;
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

            // Tab navigation
            document.querySelectorAll('.nav-tab').forEach(tab => {
                tab.addEventListener('click', (e) => {
                    const tabName = e.target.dataset.tab;
                    this.switchTab(tabName);
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

            const transferForm = document.getElementById('transferPromiseForm');
            if (transferForm) {
                transferForm.addEventListener('submit', (e) => {
                    e.preventDefault();
                    this.transferPromise();
                });
            }

            const contactForm = document.getElementById('addContactForm');
            if (contactForm) {
                contactForm.addEventListener('submit', (e) => {
                    e.preventDefault();
                    this.addContact();
                });
            }

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
    document.querySelectorAll('.nav-tab').forEach(tab => {
      tab.classList.remove('active');
    });
    document.querySelector(`[data-tab="${tabName}"]`)?.classList.add('active');

    document.querySelectorAll('.tab-pane').forEach(pane => {
      pane.classList.remove('active');
    });
    document.getElementById(tabName)?.classList.add('active');

    switch (tabName) {
      case 'dashboard':
        this.updateDashboard();
        break;
      case 'create':
        this.updateCreatePromiseForm();
        break;
      case 'my-promises':
        this.updateMyPromises();
        break;
      case 'transfer':
        this.updateTransferForm();
        break;
      case 'address-book':
        this.updateAddressBook();
        break;
    }
  }

  updateUI() {
    this.updateDashboard();
    this.updateCreatePromiseForm();
    this.updateMyPromises();
    this.updateTransferForm();
    this.updateAddressBook();
  }

  updateDashboard() {
    const sentPromises = Array.from(this.promises.values())
      .filter(p => p.senderId === this.currentUser.uid);

    const receivedPromises = Array.from(this.promises.values())
      .filter(p => p.receiverEmail === this.currentUser.email);

    const activeCount = Array.from(this.promises.values())
      .filter(p => p.status === 'active' || p.status === 'locked').length;

    const redeemedCount = Array.from(this.promises.values())
      .filter(p => p.status === 'redeemed').length;

    document.getElementById('totalPromises').textContent = this.promises.size;
    document.getElementById('activePromises').textContent = activeCount;
    document.getElementById('redeemedPromises').textContent = redeemedCount;
    document.getElementById('networkAgents').textContent = this.contacts.size + 1;

    const activityContainer = document.getElementById('recentActivity');
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
    const receiverSelect = document.getElementById('promiseReceiver');
    receiverSelect.innerHTML = '<option value="">Select a contact...</option>' +
      Array.from(this.contacts.values()).map(contact =>
        `<option value="${contact.email}">${contact.email}</option>`
      ).join('');
  }

  updateMyPromises() {
    const sentContainer = document.getElementById('sentPromises');
    const receivedContainer = document.getElementById('receivedPromises');

    const sentPromises = Array.from(this.promises.values())
      .filter(p => p.senderId === this.currentUser.uid);

    const receivedPromises = Array.from(this.promises.values())
      .filter(p => p.receiverEmail === this.currentUser.email);

    // SENT PROMISES
    sentContainer.innerHTML = sentPromises.map(promise => `
      <div class="promise-card">
        <div class="promise-content">
          ${this.decryptPromiseContent(promise)}
        </div>
        <div class="promise-meta">
          <strong>To:</strong> ${promise.receiverEmail}<br>
          <strong>Status:</strong> ${promise.status}<br>
          <strong>Created:</strong> ${new Date(promise.createdAt).toLocaleDateString()}
        </div>
        <div class="promise-actions">
          ${promise.locked ? '<span class="badge">🔒 Locked</span>' : ''}
        </div>
      </div>
    `).join('') || '<p>No promises sent yet</p>';

    // RECEIVED PROMISES
    receivedContainer.innerHTML = receivedPromises.map(promise => `
      <div class="promise-card">
        <div class="promise-content">
          ${this.decryptPromiseContent(promise)}
        </div>
        <div class="promise-meta">
          <strong>From:</strong> ${promise.senderEmail}<br>
          <strong>Status:</strong> ${promise.status}<br>
          <strong>Created:</strong> ${new Date(promise.createdAt).toLocaleDateString()}
        </div>
        <div class="promise-actions">
          ${promise.status === 'active' ? `<button onclick="app.redeemPromise('${promise.id}')">Redeem</button>` : ''}
          ${promise.status === 'active' && !promise.locked ? `<button onclick="app.showTransferUI('${promise.id}')">Transfer</button>` : ''}
        </div>
      </div>
    `).join('') || '<p>No promises received yet</p>';
  }

        updateTransferForm() {
        const selectElement = document.getElementById('transferPromiseSelect');
        const previewContainer = document.getElementById('transferPreview');

        // Populate dropdown with available promises
        const transferablePromises = Array.from(this.promises.values())
            .filter(p => p.receiverEmail === this.currentUser.email && !p.locked);

        selectElement.innerHTML = '<option value="">Select a promise...</option>' +
            transferablePromises.map(p =>
                `<option value="${p.id}">${this.decryptPromiseContent(p).substring(0, 50)}...</option>`
            ).join('');

        // Populate transfer receiver dropdown
        const receiverSelect = document.getElementById('transferReceiver');
        receiverSelect.innerHTML = '<option value="">Select a contact...</option>' +
            Array.from(this.contacts.values()).map(contact =>
                `<option value="${contact.email}">${contact.email}</option>`
            ).join('');

        // ✅ REMOVED the addEventListener from here - it's now in setupEventListeners()

        // Show current preview if a promise is already selected
        if (selectElement.value) {
            const promise = this.promises.get(selectElement.value);
            if (promise && previewContainer) {
                previewContainer.innerHTML = `
                    <div class="preview-box">
                        <strong>Promise:</strong> ${this.decryptPromiseContent(promise)}<br>
                        <strong>From:</strong> ${promise.senderEmail}<br>
                        <strong>Current Receiver:</strong> ${promise.receiverEmail}
                    </div>
                `;
            }
        }
        }


  updateAddressBook() {
    const contactsContainer = document.getElementById('contactsList');

    contactsContainer.innerHTML = Array.from(this.contacts.values()).map(contact =>
      `<div class="contact-card">
        <div class="contact-email">${contact.email}</div>
        <div class="contact-actions">
          <button onclick="app.removeContact('${contact.email}')">Remove</button>
        </div>
      </div>`
    ).join('') || '<p>No contacts added yet</p>';
  }

  // ===== UTILITIES =====
  isValidEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
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
