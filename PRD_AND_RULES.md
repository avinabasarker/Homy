# 📄 HOMY: MASTER PRD & AI SYSTEM INSTRUCTIONS
**Project:** Homy (Private E2EE Android Messenger)
**Version:** 2.0.0 | **Date:** August 22, 2026 | **Author:** Avinaba

---

## 🤖 PART 1: AI PERSONA & STRICT OPERATIONAL RULES
**YOUR ROLE:** You are an expert mobile developer, security engineer, and patient coding mentor for an absolute beginner. Your tone is encouraging, precise, and jargon-free. 

**MANDATORY RULES FOR THIS SESSION (NON-NEGOTIABLE):**
1. **NO CUSTOM CRYPTO:** You are STRICTLY FORBIDDEN from writing custom encryption math. You MUST only use `tweetnacl` via standard library implementations. The backend ONLY stores encrypted blobs.
2. **RLS IS THE SECURITY BOUNDARY:** Every Supabase table must have Row Level Security enabled with policies keyed to auth.uid(). The anon role may do nothing except sign up and sign in. Shared reads go through SECURITY DEFINER SQL functions. Never write a policy containing using (true) or with check (true).
3. **ZERO BUDGET:** You may ONLY recommend free tiers (Supabase Free, GitHub Free, EAS Free). NEVER suggest paid services, credits, or trials.
4. **ONE FILE AT A TIME:** Never give me snippets. Give me ONE complete, fully copy-pasteable file at a time.
5. **EXACT DEBUGGING:** If I paste an error, do not ask me to figure it out. Give me the EXACT replacement code for the broken file immediately.
6. **30-MINUTE PACING:** Break every task into micro-steps that take less than 30 minutes.
7. **STRICT CHECKPOINTS:** At the end of every phase, you MUST STOP. Do not proceed until I explicitly type: *"Phase X done. Proceed to Phase Y."*
8. **USE @WORKSPACE:** Always reference the actual files in the repository using `@workspace` context.

---

## 🚀 PART 2: EXECUTIVE SUMMARY & VISION
**Homy** is a 100% free, private, End-to-End Encrypted (E2EE) Android messenger for a closed circle of friends. It features a Discord-inspired, pixel-perfect UI, the server never sees plaintext, and zero financial cost. Built entirely in the cloud by a solo beginner, it distributes via manual APK and auto-updates itself. Every single interaction (messages, typing, receipts, reactions) is E2EE. No plaintext ever touches the server.

---

## 🎨 PART 3: UI/UX & DESIGN SYSTEM ("Pixel-Perfect")
**3.1. Visual Identity**
- **Theme:** Deep slate/charcoal dark mode (default). High contrast.
- **Background:** `#121212`
- **Surface (Bubbles/Cards):** `#1E1E1E`
- **Primary Accent (Electric Indigo):** `#5E5CE6`
- **Text Primary:** `#FFFFFF`
- **Text Secondary:** `#A0A0B0`
- **Typography:** *Inter* font. Chat Title (16sp/600w), Message Text (15sp/400w), Timestamps (11sp/500w).
- **Navigation:** Bottom Tab Bar (Chats, Settings).

**3.2. Chat Interface**
- **Bubbles:** 16px rounded corners. Right side (sender) gets the "tail".
- **Grouping:** Consecutive messages group together; only the last message shows the avatar/tail.
- **Timestamps:** Hidden by default. Visible on long-press or swipe.
- **Empty States:** Generic silhouette + "No messages yet. Say Hi!"
- **Avatars:** Generic silhouette for users with no profile picture.

**3.3. Animations & Haptics**
- **Incoming Messages:** Smooth slide-up/fade-in mixed with a playful pop/bounce.
- **UI Transitions:** 60fps smooth, no jank.
- **Haptics:** Device gives a light tap vibration **ONLY** when receiving a new message. No vibration on sending or UI clicks.

**3.4. Security UI**
- **App Blurring:** Heavy Gaussian blur instantly applied when app enters Android "Recent Apps" multitasking view.
- **App Lock:** PIN code required on app launch.
- **Screenshots:** Allowed. Do not block screenshots.

---

## 💬 PART 4: CORE FEATURES & FUNCTIONALITY
**4.1. Authentication & Identity**
- Auth provider: Supabase Auth. Each account is created with a hidden internal
  email <random-uuid>@users.homy.app plus the user's password. The username lives
  in a profiles table. The user never sees the email.
- Login: username + password on any device. The app maps the username
  deterministically to the hidden internal email <username>@users.homy.app
  and calls signInWithPassword. The user never sees this email.
- Username rules: 3–20 chars, lowercase letters, numbers, underscore only
  (^[a-z0-9_]{3,20}$). Stored lowercase, lookups case-insensitive.
- Password: no complexity rules; minimum 6 characters (platform minimum).
- Recovery: a 12-word BIP-39 phrase encrypts the multi-device backup. Lost
  phrase = history unrestorable on a new device (account still reachable via
  password).
- No phone numbers or real emails are ever collected.

**4.2. Messaging Lifecycle (All E2EE)**
- Encryption model: per-conversation keys derived via X25519 key agreement
  (nacl.scalarMult), never uploaded. Message bodies, reactions, edits, deletes,
  and media are end-to-end encrypted; typing and presence remain transport
  metadata (as in Signal). Forward secrecy via a symmetric ratchet is a planned
  hardening milestone.
- **Storage:** Real-time, locally stored in `expo-sqlite`.
- **Editing:** Allowed within 1 hour of sending. Shows a subtle *(edited)* tag.
- **Deleting:** "Delete for Everyone" completely vanishes the message from both devices and server (no tombstone).
- **Disappearing Messages:** Dropdown (Off / 24h / 7 days). Sender attaches encrypted metadata flag; receiver's client handles local deletion.
- **Status Indicators:** 
  - *Typing:* Three bouncing dots floating above text input.
  - *Read Receipts:* Small eye icon (read/unread).
  - *Presence:* Real-time Online/Offline status.
- **Offline Behavior:** Hitting send while offline shows error toast "You are offline". Text stays in input. On reconnect, auto-fetches missed messages.

**4.3. Interactions**
- **Reactions:** 6 emojis instantly available (👍, ❤️, 😂, 😮, 😢, 🙏). Encrypted payloads.
- **Voice Notes:** Tap to start, tap to stop. Separate "Cancel" button. AAC format. UI displays play button and scrubber bar.

**4.4. Media & File Handling**
- **Images:** Compressed locally to max 720p and <5MB. Encrypted locally before upload.
- **Videos:** Max 60 seconds, compressed to 480p. Encrypted locally before upload.
- **Link Previews:** DISABLED for privacy (no IP leaks).

---

## 🏗️ PART 5: TECHNICAL ARCHITECTURE & STACK
- **Frontend:** React Native + Expo (Managed Workflow). Tested 100% via Expo Go.
- **Backend:** Supabase (Free Tier). Supabase Auth + PostgreSQL + Realtime + Storage. RLS enforced on every table.
- **Local DB:** `expo-sqlite` for storing decrypted messages locally.
- **E2EE Library:** `tweetnacl` (X25519 + secretbox) and `expo-crypto` for randomness. No other crypto libraries.
- **Constraint:** No native-module dependencies; everything must run in Expo Go.
- **Push Notifications:** Foreground only. No background FCM (zero budget).
- **Infra Hacks:** 
  - *Keep-Alive:* GitHub Actions cron job pings Supabase every 5 mins.
  - *Auto-Cleanup:* Supabase Edge Function runs daily to delete media files older than X days.
- **Distribution:** EAS Build (free) generates `.apk`. Hosted on GitHub Releases. In-app auto-updater checks raw `version.json` on GitHub.

---

## 🗺️ PART 6: PHASED EXECUTION ROADMAP
*AI: Follow these phases strictly. Do not move to the next phase until the user says: "Phase X done. Proceed to Phase Y."*

- **Phase 1: Environment & UI Shell.** Setup GitHub Codespaces, initialize Expo, configure the dark theme, Inter font, bottom tab bar, and heavy app-blur security. Test on Expo Go.
- **Phase 2: Auth, SQLite & Supabase.** Setup Supabase tables (users, public_keys, prekeys, encrypted_backups). Implement Username/Password auth, PIN lock, 12-word seed generation, and local SQLite DB initialization.
- **Phase 3: E2EE Core & Realtime.** Implement the X3DH key exchange and Double Ratchet. Build the 1-on-1 chat UI (grouped bubbles, tails, animations). Implement encrypted typing indicators, read receipts, and presence.
- **Phase 4: Advanced Chat Features.** Implement local media compression (720p/480p) + local encryption + upload. Voice notes (AAC, tap-to-start/stop, scrubber). Reactions (6 emojis). Edit (1hr limit) & Vanish Delete. Disappearing messages.
- **Phase 5: Multi-Device, Polish & APK.** Implement encrypted DB backup/restore for multi-device login. Build the in-app auto-updater (fetching GitHub Releases). Run EAS Build for final APK.

---
**END OF DOCUMENT**