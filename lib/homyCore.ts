import AsyncStorage from '@react-native-async-storage/async-storage';
import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import * as ExpoCrypto from 'expo-crypto';
import * as SecureStore from 'expo-secure-store';
import * as SQLite from 'expo-sqlite';
import nacl from 'tweetnacl';
import { generateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';

nacl.setPRNG((target, length) => {
  const randomBytes = new Uint8Array(length);
  ExpoCrypto.getRandomValues(randomBytes);
  target.set(randomBytes);
});

const env = {
  supabaseUrl: process.env.EXPO_PUBLIC_SUPABASE_URL ?? '',
  supabaseAnonKey: process.env.EXPO_PUBLIC_SUPABASE_ANON_KEY ?? '',
};

const textEncoder = new TextEncoder();
const hasSupabaseConfig = Boolean(env.supabaseUrl && env.supabaseAnonKey);

export const supabase: SupabaseClient | null = hasSupabaseConfig
  ? createClient(env.supabaseUrl, env.supabaseAnonKey, {
      auth: {
        storage: AsyncStorage,
        autoRefreshToken: true,
        persistSession: true,
        detectSessionInUrl: false,
      },
    })
  : null;

// Kept only so the current, unchanged App.tsx continues to typecheck during M3a.
export const homyDb = SQLite.openDatabaseSync('homy.db');

function requireSupabase() {
  if (!supabase) {
    throw new Error('Supabase is not configured.');
  }
  return supabase;
}

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string) {
  const normalized = hex.trim().toLowerCase().replace(/^\\x/, '');
  if (normalized.length % 2 !== 0 || !/^[0-9a-f]*$/.test(normalized)) {
    throw new Error('Invalid bytea value.');
  }

  const output = new Uint8Array(normalized.length / 2);
  for (let index = 0; index < normalized.length; index += 2) {
    output[index / 2] = Number.parseInt(normalized.slice(index, index + 2), 16);
  }
  return output;
}

export function encodeBytesHex(bytes: Uint8Array) {
  return bytesToHex(bytes);
}

export function decodeBytesHex(hex: string) {
  return hexToBytes(hex);
}

export function encodeBytesForPostgresBytea(bytes: Uint8Array) {
  return `\\x${bytesToHex(bytes)}`;
}

export function decodeBytesFromPostgresBytea(value: string) {
  return hexToBytes(value);
}

function perUserKey(prefix: string, userId: string) {
  return `${prefix}:${userId}`;
}

function internalEmail(username: string) {
  return `${username}@users.homy.app`;
}

function pinBytes(pin: string) {
  return textEncoder.encode(pin);
}

function derivePinHash(pin: string, salt: Uint8Array) {
  let digest = new Uint8Array([...pinBytes(pin), ...salt]);
  for (let round = 0; round < 2000; round += 1) {
    digest = new Uint8Array(nacl.hash(digest));
  }
  return digest;
}

function constantTimeHexEqual(left: string, right: string) {
  const length = Math.max(left.length, right.length);
  let difference = left.length ^ right.length;
  for (let index = 0; index < length; index += 1) {
    difference |= (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
  }
  return difference === 0;
}

function validatePin(pin: string) {
  return /^\d{4,8}$/.test(pin);
}

async function upsertPresence(userId: string, online: boolean) {
  const client = requireSupabase();
  const { error } = await client.from('presence').upsert({
    user_id: userId,
    online,
    last_seen: new Date().toISOString(),
  });
  if (error) {
    throw new Error(error.message);
  }
}

async function readProfile(userId: string) {
  const client = requireSupabase();
  const { data, error } = await client
    .from('profiles')
    .select('id, username, bio, created_at')
    .eq('id', userId)
    .maybeSingle();

  if (error) {
    throw new Error(error.message);
  }
  if (!data) {
    throw new Error('Profile missing — username was not passed in signUp metadata.');
  }
  return data;
}

// AUTH (Supabase)
export function validateUsername(input: string): string | null {
  const username = input.trim().toLowerCase();
  if (/^[a-z0-9_]{3,20}$/.test(username)) {
    return null;
  }
  return 'Username must be 3–20 characters using lowercase letters, numbers, and underscores only.';
}

export async function isUsernameAvailable(username: string): Promise<boolean> {
  const normalized = username.trim().toLowerCase();
  if (validateUsername(normalized)) {
    return false;
  }

  const { data, error } = await requireSupabase().rpc('username_available', {
    p_username: normalized,
  });
  if (error) {
    throw new Error(error.message);
  }
  return data === true;
}

export async function setPin(userId: string, pin: string): Promise<boolean> {
  if (!validatePin(pin)) {
    throw new Error('PIN must contain 4 to 8 digits.');
  }

  const salt = new Uint8Array(16);
  ExpoCrypto.getRandomValues(salt);
  const payload = {
    saltHex: bytesToHex(salt),
    hashHex: bytesToHex(derivePinHash(pin, salt)),
  };
  await SecureStore.setItemAsync(perUserKey('homy_pin', userId), JSON.stringify(payload));
  return true;
}

export async function verifyPin(userId: string, pin: string): Promise<boolean> {
  if (!validatePin(pin)) {
    return false;
  }

  const raw = await SecureStore.getItemAsync(perUserKey('homy_pin', userId));
  if (!raw) {
    return false;
  }

  try {
    const payload = JSON.parse(raw) as { saltHex: string; hashHex: string };
    const actualHash = bytesToHex(derivePinHash(pin, hexToBytes(payload.saltHex)));
    return constantTimeHexEqual(actualHash, payload.hashHex);
  } catch {
    return false;
  }
}

export async function ensureDeviceKeys(userId: string): Promise<void> {
  const privateKeyName = perUserKey('homy_id_sk', userId);
  if (await SecureStore.getItemAsync(privateKeyName)) {
    return;
  }

  const client = requireSupabase();
  const identity = nacl.box.keyPair();
  const prekey = nacl.box.keyPair();
  const identitySecret = bytesToHex(identity.secretKey);
  const identityPublic = bytesToHex(identity.publicKey);
  const prekeySecret = bytesToHex(prekey.secretKey);

  await SecureStore.setItemAsync(privateKeyName, identitySecret);
  await SecureStore.setItemAsync(perUserKey('homy_id_pk', userId), identityPublic);
  await SecureStore.setItemAsync(perUserKey('homy_prekey_sk', userId), prekeySecret);

  const { error: identityError } = await client.from('public_keys').upsert({
    user_id: userId,
    identity_key: encodeBytesForPostgresBytea(identity.publicKey),
    updated_at: new Date().toISOString(),
  });
  if (identityError) {
    throw new Error(identityError.message);
  }

  const { error: prekeyError } = await client.from('prekeys').insert({
    user_id: userId,
    prekey: encodeBytesForPostgresBytea(prekey.publicKey),
  });
  if (prekeyError) {
    throw new Error(prekeyError.message);
  }
}

export async function registerAccount(
  usernameInput: string,
  password: string,
  pin: string,
): Promise<{ userId: string; username: string; mnemonic: string }> {
  const usernameError = validateUsername(usernameInput);
  if (usernameError) {
    throw new Error(usernameError);
  }
  if (!validatePin(pin)) {
    throw new Error('PIN must contain 4 to 8 digits.');
  }

  const username = usernameInput.trim().toLowerCase();
  if (!(await isUsernameAvailable(username))) {
    throw new Error('That username is taken.');
  }

  const client = requireSupabase();
  const identity = nacl.box.keyPair();
  const prekey = nacl.box.keyPair();
  const mnemonic = generateMnemonic(wordlist, 128);
  const { data, error } = await client.auth.signUp({
    email: internalEmail(username),
    password,
    options: { data: { username } },
  });

  if (error) {
    if (/already registered|already exists|user already registered/i.test(error.message)) {
      throw new Error('That username is taken.');
    }
    throw new Error(error.message);
  }
  if (!data.session || !data.user) {
    throw new Error("Email confirmation is still enabled in the Supabase dashboard (Authentication -> Sign In / Providers -> Email). Turn 'Confirm email' off and try again.");
  }

  const userId = data.user.id;
  await SecureStore.setItemAsync(perUserKey('homy_id_sk', userId), bytesToHex(identity.secretKey));
  await SecureStore.setItemAsync(perUserKey('homy_id_pk', userId), bytesToHex(identity.publicKey));
  await SecureStore.setItemAsync(perUserKey('homy_prekey_sk', userId), bytesToHex(prekey.secretKey));
  await SecureStore.setItemAsync(perUserKey('homy_recovery', userId), mnemonic);

  const { error: identityError } = await client.from('public_keys').upsert({
    user_id: userId,
    identity_key: encodeBytesForPostgresBytea(identity.publicKey),
  });
  if (identityError) {
    throw new Error(identityError.message);
  }

  const { error: prekeyError } = await client.from('prekeys').insert({
    user_id: userId,
    prekey: encodeBytesForPostgresBytea(prekey.publicKey),
  });
  if (prekeyError) {
    throw new Error(prekeyError.message);
  }

  await upsertPresence(userId, true);
  await setPin(userId, pin);

  return { userId, username, mnemonic };
}

export async function loginAccount(
  usernameInput: string,
  password: string,
): Promise<{ userId: string; username: string; needsPinSetup: boolean }> {
  const usernameError = validateUsername(usernameInput);
  if (usernameError) {
    throw new Error(usernameError);
  }

  const username = usernameInput.trim().toLowerCase();
  const { data, error } = await requireSupabase().auth.signInWithPassword({
    email: internalEmail(username),
    password,
  });
  if (error) {
    if (/invalid login credentials/i.test(error.message)) {
      throw new Error('Wrong username or password.');
    }
    throw new Error(error.message);
  }
  if (!data.session?.user) {
    throw new Error('Login did not create a session.');
  }

  const userId = data.session.user.id;
  const profile = await readProfile(userId);
  await ensureDeviceKeys(userId);
  await upsertPresence(userId, true);
  const needsPinSetup = !(await SecureStore.getItemAsync(perUserKey('homy_pin', userId)));

  return { userId, username: profile.username, needsPinSetup };
}

export async function restoreSession(): Promise<{ userId: string; username: string; needsPinSetup: boolean } | null> {
  try {
    const client = requireSupabase();
    const { data, error } = await client.auth.getSession();
    if (error || !data.session?.user) {
      return null;
    }

    const userId = data.session.user.id;
    const profile = await readProfile(userId);
    await ensureDeviceKeys(userId);
    const needsPinSetup = !(await SecureStore.getItemAsync(perUserKey('homy_pin', userId)));
    return { userId, username: profile.username, needsPinSetup };
  } catch {
    return null;
  }
}

export async function signOut(userId: string): Promise<void> {
  try {
    await upsertPresence(userId, false);
  } catch {
    // Sign-out must still proceed if presence is unavailable.
  }
  if (supabase) {
    await supabase.auth.signOut();
  }
}

export function startPresenceHeartbeat(userId: string): () => void {
  const beat = () => {
    void upsertPresence(userId, true).catch(() => undefined);
  };
  beat();
  const timer = setInterval(beat, 45_000);
  return () => clearInterval(timer);
}

export async function getUserProfile(userId: string) {
  const profile = await readProfile(userId);
  return { username: profile.username, profile_bio: profile.bio };
}

export async function updateUserProfile(userId: string, profileBio: string) {
  const { data, error } = await requireSupabase()
    .from('profiles')
    .update({ bio: profileBio.trim().slice(0, 160) })
    .eq('id', userId)
    .select('username, bio')
    .single();
  if (error) {
    throw new Error(error.message);
  }
  return { username: data.username as string, profile_bio: data.bio as string };
}

export async function getSupabaseStatus() {
  return hasSupabaseConfig
    ? { connected: true }
    : { connected: false, error: 'Missing EXPO_PUBLIC_SUPABASE_URL or EXPO_PUBLIC_SUPABASE_ANON_KEY' };
}

// Temporary compatibility adapters for the unchanged pre-M3a UI. They do not
// recreate the old local users table or old message schema.
export async function initializeLocalDatabase() {
  return homyDb;
}

export function hashSecret(value: string) {
  return bytesToHex(nacl.hash(textEncoder.encode(value)));
}

export async function getStoredSession() {
  const session = await restoreSession();
  return session ? { ...session, deviceId: '', signedInAt: '' } : null;
}

export async function clearSession() {
  const { data } = supabase ? await supabase.auth.getSession() : { data: { session: null } };
  if (data.session?.user) {
    await signOut(data.session.user.id);
  }
}

export async function loginLocalUser(username: string, password: string, _pin: string) {
  const result = await loginAccount(username, password);
  return { id: result.userId, username: result.username };
}

export async function registerLocalUser(username: string, password: string, pin: string) {
  const result = await registerAccount(username, password, pin);
  return {
    userId: result.userId,
    username: result.username,
    recoveryPhrase: result.mnemonic,
  };
}

export async function setPresence(userId: string, status: 'online' | 'offline') {
  await upsertPresence(userId, status === 'online');
}

export async function listContacts(_ownerId: string) {
  return [];
}

export async function syncAcceptedContacts(_ownerId: string) {
  return [];
}

export async function listIncomingFriendRequests(_ownerId: string) {
  return [];
}

export async function sendFriendRequest(_ownerId: string, _username: string): Promise<{ recipient_username: string }> {
  throw new Error('Friend requests will be rebuilt against the locked schema in the next milestone.');
}

export async function respondToFriendRequest(_ownerId: string, _requestId: string, _accept: boolean) {
  throw new Error('Friend requests will be rebuilt against the locked schema in the next milestone.');
}

export async function getPeerPresence(_ownerId: string, _peerUsername: string) {
  return { status: 'unknown', lastSeenAt: null as string | null };
}

export async function getPeerTypingState(_ownerId: string, _peerUsername: string) {
  return false;
}

export async function getReadReceiptSummary(_ownerId: string, _peerUsername: string) {
  return { peerReadCount: 0 };
}

export async function setTypingState(_ownerId: string, _peerUsername: string, _isTyping: boolean) {
  return undefined;
}

export async function sendEncryptedMessage(_ownerId: string, _peerUsername: string, _plaintext: string) {
  throw new Error('Messaging will be rebuilt against the locked schema in the next milestone.');
}

export async function syncAndDecryptMessages(_ownerId: string, _peerUsername: string) {
  return [] as Array<{ id: string; senderId: string; text: string; sentAt: string }>;
}

export function subscribeToConversationMessages(
  _ownerId: string,
  _peerUserId: string,
  _onMessage: () => void,
) {
  return () => undefined;
}
