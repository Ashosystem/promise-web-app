// Firebase Promise App - Multi-User Implementation with Real-time Sync
class FirebasePromiseApp {
  constructor() {
    this.currentUser = null;
    this.currentUserDoc = null;
    this.promises = new Map();
    this.contacts = new Map();
    this.activities = [];

    // Firebase references (initialized in index.html)
    this.auth = firebase.auth();
    console.log('Firebase initialized:', { auth: firebase.auth, db: firebase.firestore });
    this.db = firebase.firestore();


    // Real-time listeners
    this.unsubscribers = [];

    this.initializeAuth();
  }

  // ===== AUTHENTICATION =====
  initializeAuth() {
    // Check if user already logged in
    this.auth.onAuthStateChanged(async (user) => {
      if (user) {
        this.currentUser = user;
        await this.loadUserProfile();
        this.showApp();
        this.setupRealtimeListeners();
      } else {
        this.showAuthScreen();
      }
    });

    // Auth form listeners
    document.getElementById('loginForm').addEventListener('submit', (e) => {
      e.preventDefault();
      this.login();
    });

    document.getElementById('signupForm').addEventListener('submit', (e) => {
      e.preventDefault();
      this.signup();
    });

    // Auth tab switching
    document.getElementById('loginTab').addEventListener('click', () => {
      this.switchAuthMode('login');
    });

    document.getElementById('signupTab').addEventListener('click', () => {
      this.switchAuthMode('signup');
    });
  }

  switchAuthMode(mode) {
    document.querySelectorAll('.auth-tab').forEach(tab => {
      tab.classList.remove('active');
    });
    document.querySelector(`[data-mode="${mode}"]`).classList.add('active');

    document.querySelectorAll('.auth-form').forEach(form => {
      form.classList.remove('active');
    });

    if (mode === 'login') {
      document.getElementById('loginForm').classList.add('active');
    } else {
      document.getElementById('signupForm').classList.add('active');
    }
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
  console.log('Email:', email, 'Password length:', password.length);

  if (password.length < 6) {
    console.log('Password too short');
    document.getElementById('signupError').textContent = 'Password must be at least 6 characters';
    return;
  }

  try {
    console.log('Creating user with Firebase Auth...');
    const userCred = await this.auth.createUserWithEmailAndPassword(email, password);
    console.log('User created:', userCred.user.uid);

    console.log('Creating Firestore user doc...');
    await this.db.collection('users').doc(userCred.user.uid).set({
      email: email,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    });
    console.log('User doc created successfully');
    // onAuthStateChanged will handle the rest
  } catch (error) {
    console.error('SIGNUP ERROR:', error);
    console.error('Error code:', error.code);
    console.error('Error message:', error.message);
    document.getElementById('signupError').textContent = error.message;
  }
}


  async logout() {
    // Clean up listeners
    this.unsubscribers.forEach(unsub => unsub());
    this.unsubscribers = [];

    await this.auth.signOut();
  }

  // ===== USER PROFILE =====
  async loadUserProfile() {
    const userDocRef = this.db.collection('users').doc(this.currentUser.uid);

    try {
      const doc = await userDocRef.get();
      if (doc.exists) {
        this.currentUserDoc = doc.data();
      } else {
        // Create profile if doesn't exist
        await userDocRef.set({
          email: this.currentUser.email,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        });
        this.currentUserDoc = (await userDocRef.get()).data();
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

    if (!content || !receiverEmail) {
      this.showToast('Please fill in all required fields', 'error');
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

      // Create promise in Firestore
      await this.db.collection('promises').add({
        content: content,
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
      });

      document.getElementById('createPromiseForm').reset();
      this.showToast('Promise created successfully', 'success');
      this.addActivity(`Promise "${content}" created for ${receiverEmail}`);

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

  console.log('Selected promise ID:', promiseId);
  console.log('New receiver email:', newReceiverEmail);

  if (!promiseId || !newReceiverEmail) {
    console.log('Validation failed - empty fields');
    this.showToast('Please select a promise and new receiver', 'error');
    return;
  }

  const promise = this.promises.get(promiseId);
  console.log('Promise object:', promise);

  if (!promise) {
    console.log('Promise not found in map');
    this.showToast('Promise not found', 'error');
    return;
  }

  if (promise.locked) {
    console.log('Promise is locked');
    this.showToast('Cannot transfer locked promise', 'error');
    return;
  }

  // Check if user owns or received this promise
    // Check if user owns or received this promise
    if (promise.senderId !== this.currentUser.uid && promise.receiverEmail !== this.currentUser.email) {
      console.log('User does not own or received this promise');
      this.showToast('You can only transfer promises you own or received', 'error');
      return;
    }

    // Senders cannot transfer - only current receivers can
    if (promise.senderId === this.currentUser.uid) {
      console.log('Sender cannot transfer promise - only current receiver can');
      this.showToast('Only the current receiver can transfer this promise', 'error');
      return;
    }


  this.showLoading();
  try {
    console.log('Looking up new receiver...');
    const userQuery = await this.db.collection('users')
      .where('email', '==', newReceiverEmail)
      .get();

    console.log('User query result:', userQuery.size, 'docs');

    if (userQuery.empty) {
      console.log('New receiver not found');
      this.showToast('New receiver not found', 'error');
      this.hideLoading();
      return;
    }

    const newReceiverId = userQuery.docs[0].id;
    console.log('New receiver ID:', newReceiverId);

    // Update promise
    console.log('Updating promise in Firestore...');
    await this.db.collection('promises').doc(promiseId).update({
      receiverId: newReceiverId,
      receiverEmail: newReceiverEmail,
      updatedAt: new Date().toISOString(),
      transferHistory: firebase.firestore.FieldValue.arrayUnion({
        from: promise.receiverEmail,
        to: newReceiverEmail,
        timestamp: new Date().toISOString()
      })
    });

    console.log('Promise transferred successfully');
    document.getElementById('transferPromiseForm').reset();
    this.showToast('Promise transferred successfully', 'success');
    this.addActivity(`Promise "${promise.content}" transferred to ${newReceiverEmail}`);
  } catch (error) {
    console.error('TRANSFER ERROR:', error);
    console.error('Error code:', error.code);
    console.error('Error message:', error.message);
    this.showToast('Failed to transfer promise', 'error');
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
      this.addActivity(`Promise "${promise.content}" redeemed`);

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

    if (email === this.currentUser.email) {
      this.showToast('Cannot add yourself as a contact', 'error');
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

      await this.db.collection('users')
        .doc(this.currentUser.uid)
        .collection('contacts')
        .doc(contactUserId)
        .set({
          email: email,
          addedAt: new Date().toISOString()
        });

      document.getElementById('addContactForm').reset();
      this.showToast('Contact added successfully', 'success');
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
showApp() {
  console.log('Showing app container...');
  document.getElementById('authScreen').classList.add('hidden');
  document.getElementById('appContainer').classList.remove('hidden');
  // Update header with user info
  document.getElementById('currentAgentKey').textContent = this.currentUser.email;
  console.log('Calling setupEventListeners...');
  this.setupEventListeners();
  console.log('Calling updateUI...');
  this.updateUI();
  console.log('App fully loaded');
  this.hideLoading();  // ← ADD THIS LINE
}


  showAuthScreen() {
    document.getElementById('authScreen').classList.remove('hidden');
    document.getElementById('appContainer').classList.add('hidden');
        // Auth form listeners
    document.getElementById('loginForm').addEventListener('submit', (e) => {
      e.preventDefault();
      this.login();
    });

    document.getElementById('signupForm').addEventListener('submit', (e) => {
      e.preventDefault();
      this.signup();
    });

    // Auth tab switching
    document.getElementById('loginTab').addEventListener('click', () => {
      this.switchAuthMode('login');
    });

    document.getElementById('signupTab').addEventListener('click', () => {
      this.switchAuthMode('signup');
    });
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

    switch(tabName) {
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
      activityContainer.innerHTML = `
        <div class="empty-state">
          <h3>No recent activity</h3>
          <p>Create or receive promises to get started</p>
        </div>
      `;
    } else {
      activityContainer.innerHTML = this.activities
        .slice(-5)
        .reverse()
        .map(activity => `
          <div class="activity-item">
            <div>${activity.text}</div>
            <div class="activity-time">${this.formatDate(activity.timestamp)}</div>
          </div>
        `).join('');
    }
  }

  updateCreatePromiseForm() {
    const select = document.getElementById('promiseReceiver');
    const currentValue = select.value;

    select.innerHTML = '<option value="">Select a contact...</option>';
    this.contacts.forEach((contact) => {
      const option = document.createElement('option');
      option.value = contact.email;
      option.textContent = contact.email;
      select.appendChild(option);
    });

    select.value = currentValue;
  }

  updateMyPromises() {
    const sentContainer = document.getElementById('sentPromises');
    const receivedContainer = document.getElementById('receivedPromises');

    const sent = Array.from(this.promises.values())
      .filter(p => p.senderId === this.currentUser.uid);
    const received = Array.from(this.promises.values())
      .filter(p => p.receiverEmail === this.currentUser.email);

    sentContainer.innerHTML = sent.length === 0
      ? '<div class="empty-state"><p>No promises sent yet</p></div>'
      : sent.map(p => this.renderPromiseCard(p, 'sent')).join('');

    receivedContainer.innerHTML = received.length === 0
      ? '<div class="empty-state"><p>No promises received yet</p></div>'
      : received.map(p => this.renderPromiseCard(p, 'received')).join('');
  }

  renderPromiseCard(promise, type) {
    const other = type === 'sent' ? promise.receiverEmail : promise.senderEmail;
    const isReceiver = type === 'received';

    return `
      <div class="promise-item">
        <div class="promise-header">
          <div class="promise-content">${promise.content}</div>
          <span class="promise-status ${promise.status}">${promise.status.toUpperCase()}</span>
        </div>
        <div class="promise-meta">
          <span>${isReceiver ? 'From' : 'To'}: ${other}</span>
          ${promise.expiresAt ? `<span>Expires: ${this.formatDate(promise.expiresAt)}</span>` : ''}
          ${promise.locked ? '<span>🔒 Locked</span>' : ''}
        </div>
        <div class="promise-actions">
          ${isReceiver && promise.status === 'active' ?
            `<button class="btn btn--sm btn--primary" onclick="app.redeemPromise('${promise.id}')">Redeem</button>` : ''
          }
            ${
              (promise.senderId === this.currentUser.uid || promise.receiverEmail === this.currentUser.email) &&
              !promise.locked &&
              promise.status !== 'redeemed' ?
                `<button class="btn btn--sm btn--secondary" onclick="app.showTransferUI('${promise.id}')">Transfer</button>`
                : ''
            }

        </div>
      </div>
    `;
  }

  updateTransferForm() {
    const select = document.getElementById('transferPromiseSelect');
    const receiverSelect = document.getElementById('transferReceiver');
    const currentPromise = select.value;
    const currentReceiver = receiverSelect.value;

  const transferable = Array.from(this.promises.values())
  .filter(p => !p.locked && p.status !== 'redeemed' && p.receiverEmail === this.currentUser.email)



    select.innerHTML = '<option value="">Select a promise...</option>';
    transferable.forEach(p => {
      const option = document.createElement('option');
      option.value = p.id;
      option.textContent = `${p.content.substring(0, 30)}... (${p.receiverEmail})`;
      select.appendChild(option);
    });

    select.value = currentPromise;

    receiverSelect.innerHTML = '<option value="">Select a contact...</option>';
    this.contacts.forEach((contact) => {
      const option = document.createElement('option');
      option.value = contact.email;
      option.textContent = contact.email;
      receiverSelect.appendChild(option);
    });

    receiverSelect.value = currentReceiver;
  }

  updateAddressBook() {
    const container = document.getElementById('contactsList');

    if (this.contacts.size === 0) {
      container.innerHTML = '<div class="empty-state"><p>No contacts added yet</p></div>';
    } else {
      container.innerHTML = Array.from(this.contacts.values())
        .map(contact => `
          <div class="contact-item">
            <div class="contact-info">
              <div class="contact-name">${contact.email}</div>
            </div>
            <div class="contact-actions">
              <button class="btn btn--sm btn--outline" onclick="app.removeContact('${contact.email}')">Remove</button>
            </div>
          </div>
        `).join('');
    }
  }

  addActivity(text) {
    this.activities.push({
      text: text,
      timestamp: new Date().toISOString()
    });
    // Keep only last 50 activities
    if (this.activities.length > 50) {
      this.activities.shift();
    }
    this.updateDashboard();
  }

  // ===== UTILITIES =====
  isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  formatDate(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;

    return date.toLocaleDateString();
  }

  showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer') ||
                     (() => {
                       const div = document.createElement('div');
                       div.id = 'toastContainer';
                       div.className = 'toast-container';
                       document.body.appendChild(div);
                       return div;
                     })();

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => toast.remove(), 4000);
  }

  showLoading() {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) overlay.classList.remove('hidden');
  }

  hideLoading() {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) overlay.classList.add('hidden');
  }
}

// Initialize the app when DOM is ready
// Initialize the app when DOM is ready
let app;
document.addEventListener('DOMContentLoaded', () => {
  app = new FirebasePromiseApp();
});
