import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import ExpoCrypto from 'expo-crypto/build/ExpoCrypto';
import * as SQLite from 'expo-sqlite';
import * as SecureStore from 'expo-secure-store';
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
const textDecoder = new TextDecoder();

const SESSION_KEY = 'homy_session';
const DEVICE_ID_KEY = 'homy_device_id';
const PRIVATE_KEY_KEY = 'homy_private_key';
const PUBLIC_KEY_KEY = 'homy_public_key';
const PREKEY_PRIVATE_STORE_KEY = 'homy_prekey_private_store';

const secureStoreAdapter = {
  getItem: async (key: string) => {
    const value = await SecureStore.getItemAsync(key);
    return value ?? null;
  },
  setItem: async (key: string, value: string) => {
    await SecureStore.setItemAsync(key, value);
  },
  removeItem: async (key: string) => {
    await SecureStore.deleteItemAsync(key);
  },
};

const hasSupabaseConfig = Boolean(env.supabaseUrl && env.supabaseAnonKey);

export const supabase: SupabaseClient | null = hasSupabaseConfig
  ? createClient(env.supabaseUrl, env.supabaseAnonKey, {
      auth: {
        persistSession: true,
        autoRefreshToken: true,
        detectSessionInUrl: false,
        storage: secureStoreAdapter,
      },
    })
  : null;

export const homyDb = SQLite.openDatabaseSync('homy.db');

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string) {
  const normalized = hex.trim().toLowerCase();
  if (normalized.length % 2 !== 0) {
    throw new Error('Invalid hex length.');
  }

  const output = new Uint8Array(normalized.length / 2);
  for (let index = 0; index < normalized.length; index += 2) {
    const byteHex = normalized.slice(index, index + 2);
    const parsed = Number.parseInt(byteHex, 16);
    if (Number.isNaN(parsed)) {
      throw new Error('Invalid hex value.');
    }
    output[index / 2] = parsed;
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

export function decodeBytesFromPostgresBytea(byteaValue: string) {
  const trimmed = byteaValue.trim();
  if (!trimmed.startsWith('\\x')) {
    throw new Error('Invalid bytea format.');
  }

  return hexToBytes(trimmed.slice(2));
}

function concatBytes(chunks: Uint8Array[]) {
  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(totalLength);
  let offset = 0;

  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }

  return out;
}

function deriveInitiatorSharedSecret(
  initiatorIdentityPrivateKey: Uint8Array,
  initiatorEphemeralSecretKey: Uint8Array,
  recipientIdentityPublicKey: Uint8Array,
  recipientPrekeyPublicKey: Uint8Array,
) {
  const dh1 = nacl.scalarMult(initiatorIdentityPrivateKey, recipientPrekeyPublicKey);
  const dh2 = nacl.scalarMult(initiatorEphemeralSecretKey, recipientIdentityPublicKey);
  const dh3 = nacl.scalarMult(initiatorEphemeralSecretKey, recipientPrekeyPublicKey);
  return nacl.hash(concatBytes([dh1, dh2, dh3])).slice(0, 32);
}

function deriveResponderSharedSecret(
  responderIdentityPrivateKey: Uint8Array,
  responderPrekeyPrivateKey: Uint8Array,
  initiatorIdentityPublicKey: Uint8Array,
  initiatorEphemeralPublicKey: Uint8Array,
) {
  const dh1 = nacl.scalarMult(responderPrekeyPrivateKey, initiatorIdentityPublicKey);
  const dh2 = nacl.scalarMult(responderIdentityPrivateKey, initiatorEphemeralPublicKey);
  const dh3 = nacl.scalarMult(responderPrekeyPrivateKey, initiatorEphemeralPublicKey);
  return nacl.hash(concatBytes([dh1, dh2, dh3])).slice(0, 32);
}

async function getStoredPrekeyPrivateMap() {
  const raw = await SecureStore.getItemAsync(PREKEY_PRIVATE_STORE_KEY);
  if (!raw) {
    return {} as Record<string, number[]>;
  }

  try {
    return JSON.parse(raw) as Record<string, number[]>;
  } catch {
    return {} as Record<string, number[]>;
  }
}

function getPrekeyPrivateKeyFromMap(store: Record<string, number[]>, keyId: string) {
  const value = store[keyId];
  if (!value) {
    return null;
  }
  return Uint8Array.from(value);
}

async function saveStoredPrekeyPrivateMap(value: Record<string, number[]>) {
  await SecureStore.setItemAsync(PREKEY_PRIVATE_STORE_KEY, JSON.stringify(value));
}

async function upsertRemoteIdentityPublicKey(userId: string, deviceId: string, publicKey: Uint8Array, now: string) {
  if (!supabase) {
    return;
  }

  const remotePayload = {
    id: `pk_${userId}_${deviceId}`,
    user_id: userId,
    device_id: deviceId,
    public_key: encodeBytesForPostgresBytea(publicKey),
    created_at: now,
  };

  const { error } = await supabase.from('public_keys').upsert(remotePayload, { onConflict: 'id' });
  if (error) {
    throw new Error(error.message);
  }
}

type LocalPrekeyRecord = {
  keyId: string;
  publicKey: Uint8Array;
};

export async function generateAndStorePrekeys(userId: string, count = 10) {
  if (count < 1) {
    return [] as LocalPrekeyRecord[];
  }

  const now = new Date().toISOString();
  const privateMap = await getStoredPrekeyPrivateMap();
  const records: LocalPrekeyRecord[] = [];

  for (let index = 0; index < count; index += 1) {
    const keyPair = nacl.box.keyPair();
    const keyId = `prekey_${Date.now()}_${index}_${Math.random().toString(16).slice(2)}`;

    privateMap[keyId] = Array.from(keyPair.secretKey);

    await homyDb.runAsync(
      'INSERT OR REPLACE INTO prekeys (id, user_id, key_id, public_key, created_at) VALUES (?, ?, ?, ?, ?)',
      [
        `local_${keyId}`,
        userId,
        keyId,
        Uint8Array.from(keyPair.publicKey),
        now,
      ],
    );

    records.push({ keyId, publicKey: keyPair.publicKey });
  }

  await saveStoredPrekeyPrivateMap(privateMap);
  return records;
}

async function publishPrekeysRemote(userId: string, prekeys: LocalPrekeyRecord[], now: string) {
  if (!supabase || prekeys.length === 0) {
    return;
  }

  const payload = prekeys.map((entry) => ({
    id: `spk_${entry.keyId}`,
    user_id: userId,
    key_id: entry.keyId,
    public_key: encodeBytesForPostgresBytea(entry.publicKey),
    created_at: now,
  }));

  const { error } = await supabase.from('prekeys').upsert(payload, { onConflict: 'id' });
  if (error) {
    throw new Error(error.message);
  }
}

export async function fetchRemoteContactBundle(usernameValue: string) {
  if (!supabase) {
    throw new Error('Supabase is not configured.');
  }

  const username = usernameValue.trim();
  const { data: userRow, error: userError } = await supabase
    .from('users')
    .select('id, username')
    .eq('username', username)
    .maybeSingle();

  if (userError) {
    throw new Error(userError.message);
  }

  if (!userRow) {
    throw new Error('User not found.');
  }

  const { data: identityRows, error: identityError } = await supabase
    .from('public_keys')
    .select('device_id, public_key, created_at')
    .eq('user_id', userRow.id)
    .order('created_at', { ascending: false })
    .limit(1);

  if (identityError) {
    throw new Error(identityError.message);
  }

  const identityRow = identityRows?.[0];
  if (!identityRow?.public_key) {
    throw new Error('Identity key not found for this user.');
  }

  const { data: prekeyRows, error: prekeyError } = await supabase
    .from('prekeys')
    .select('key_id, public_key, created_at')
    .eq('user_id', userRow.id)
    .order('created_at', { ascending: false })
    .limit(1);

  if (prekeyError) {
    throw new Error(prekeyError.message);
  }

  const prekeyRow = prekeyRows?.[0];
  if (!prekeyRow?.public_key) {
    throw new Error('Prekey not found for this user.');
  }

  return {
    userId: userRow.id as string,
    username: userRow.username as string,
    deviceId: identityRow.device_id as string,
    identityPublicKey: decodeBytesFromPostgresBytea(identityRow.public_key as string),
    prekeyId: prekeyRow.key_id as string,
    prekeyPublicKey: decodeBytesFromPostgresBytea(prekeyRow.public_key as string),
  };
}

export async function deriveX3DHSharedSecret(ownerUserId: string, contactUsername: string) {
  const identity = await getOrCreateIdentityKeys();
  const bundle = await fetchRemoteContactBundle(contactUsername);
  const ephemeral = nacl.box.keyPair();
  const rootKey = deriveInitiatorSharedSecret(
    identity.privateKey,
    ephemeral.secretKey,
    bundle.identityPublicKey,
    bundle.prekeyPublicKey,
  );

  return {
    ownerUserId,
    peerUserId: bundle.userId,
    peerUsername: bundle.username,
    peerDeviceId: bundle.deviceId,
    peerPrekeyId: bundle.prekeyId,
    rootKey,
    myEphemeralPublicKey: ephemeral.publicKey,
    myEphemeralSecretKey: ephemeral.secretKey,
  };
}

export function hashSecret(value: string) {
  return bytesToHex(nacl.hash(new TextEncoder().encode(value)));
}

export function generateRecoveryPhrase(): string {
  return generateMnemonic(wordlist, 128);
}

export function generateDeviceId() {
  return `device_${bytesToHex(nacl.randomBytes(8))}`;
}

export function generateDeviceKeyPair() {
  return nacl.box.keyPair();
}

export async function getOrCreateIdentityKeys() {
  const existingPrivate = await SecureStore.getItemAsync(PRIVATE_KEY_KEY);
  const existingPublic = await SecureStore.getItemAsync(PUBLIC_KEY_KEY);

  if (existingPrivate && existingPublic) {
    return {
      privateKey: Uint8Array.from(JSON.parse(existingPrivate)),
      publicKey: Uint8Array.from(JSON.parse(existingPublic)),
    };
  }

  const keyPair = generateDeviceKeyPair();
  await SecureStore.setItemAsync(PRIVATE_KEY_KEY, JSON.stringify(Array.from(keyPair.secretKey)));
  await SecureStore.setItemAsync(PUBLIC_KEY_KEY, JSON.stringify(Array.from(keyPair.publicKey)));

  return {
    privateKey: keyPair.secretKey,
    publicKey: keyPair.publicKey,
  };
}

export async function initializeLocalDatabase() {
  await homyDb.execAsync(`
    PRAGMA journal_mode = WAL;

    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      recovery_phrase TEXT NOT NULL,
      pin_hash TEXT NOT NULL,
      profile_bio TEXT NOT NULL DEFAULT '',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS public_keys (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      public_key BLOB NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, device_id)
    );

    CREATE TABLE IF NOT EXISTS prekeys (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      key_id TEXT NOT NULL,
      public_key BLOB NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, key_id)
    );

    CREATE TABLE IF NOT EXISTS encrypted_backups (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      backup_blob BLOB NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, device_id)
    );

    CREATE TABLE IF NOT EXISTS contacts (
      id TEXT PRIMARY KEY,
      owner_id TEXT NOT NULL,
      contact_user_id TEXT,
      username TEXT NOT NULL,
      public_key BLOB,
      device_id TEXT,
      status TEXT DEFAULT 'active',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(owner_id, username)
    );

    CREATE TABLE IF NOT EXISTS friend_requests (
      id TEXT PRIMARY KEY,
      requester_id TEXT NOT NULL,
      recipient_id TEXT NOT NULL,
      requester_username TEXT NOT NULL,
      recipient_username TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      responded_at TEXT
    );

    CREATE TABLE IF NOT EXISTS conversations (
      id TEXT PRIMARY KEY,
      user_a TEXT NOT NULL,
      user_b TEXT NOT NULL,
      last_message TEXT,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      conversation_id TEXT NOT NULL,
      sender_id TEXT NOT NULL,
      recipient_id TEXT NOT NULL,
      ciphertext BLOB NOT NULL,
      nonce BLOB NOT NULL,
      x3dh_ephemeral_public_key BLOB,
      x3dh_prekey_id TEXT,
      sent_at TEXT DEFAULT CURRENT_TIMESTAMP,
      edited_at TEXT,
      deleted_for_everyone INTEGER DEFAULT 0,
      disappearing_mode TEXT DEFAULT 'off'
    );

    CREATE TABLE IF NOT EXISTS ratchet_sessions (
      id TEXT PRIMARY KEY,
      owner_id TEXT NOT NULL,
      peer_user_id TEXT NOT NULL,
      peer_username TEXT NOT NULL,
      peer_device_id TEXT,
      peer_prekey_id TEXT,
      root_key BLOB NOT NULL,
      my_ephemeral_public_key BLOB NOT NULL,
      my_ephemeral_secret_key BLOB NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(owner_id, peer_user_id)
    );

    CREATE TABLE IF NOT EXISTS read_receipts (
      id TEXT PRIMARY KEY,
      message_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      read_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(message_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS typing_events (
      id TEXT PRIMARY KEY,
      conversation_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      is_typing INTEGER DEFAULT 0,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(conversation_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS presence (
      user_id TEXT PRIMARY KEY,
      status TEXT NOT NULL DEFAULT 'offline',
      last_seen_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);

  try {
    await homyDb.execAsync('ALTER TABLE messages ADD COLUMN x3dh_ephemeral_public_key BLOB;');
  } catch {
    // Column already exists on upgraded installs.
  }

  try {
    await homyDb.execAsync('ALTER TABLE messages ADD COLUMN x3dh_prekey_id TEXT;');
  } catch {
    // Column already exists on upgraded installs.
  }

  try {
    await homyDb.execAsync('ALTER TABLE contacts ADD COLUMN contact_user_id TEXT;');
  } catch {
    // Column already exists on upgraded installs.
  }

  try {
    await homyDb.execAsync("ALTER TABLE users ADD COLUMN profile_bio TEXT NOT NULL DEFAULT ''; ");
  } catch {
    // Column already exists on upgraded installs.
  }

  return homyDb;
}

export async function saveSession(userId: string, username: string) {
  const deviceId = (await SecureStore.getItemAsync(DEVICE_ID_KEY)) ?? generateDeviceId();
  await SecureStore.setItemAsync(DEVICE_ID_KEY, deviceId);

  const payload = {
    userId,
    username,
    deviceId,
    signedInAt: new Date().toISOString(),
  };

  await SecureStore.setItemAsync(SESSION_KEY, JSON.stringify(payload));
  return payload;
}

export async function getStoredSession() {
  const raw = await SecureStore.getItemAsync(SESSION_KEY);
  if (!raw) {
    return null;
  }

  try {
    return JSON.parse(raw) as {
      userId: string;
      username: string;
      deviceId: string;
      signedInAt: string;
    };
  } catch {
    return null;
  }
}

export async function clearSession() {
  await SecureStore.deleteItemAsync(SESSION_KEY);
}

export async function isUserLoggedIn() {
  const session = await getStoredSession();
  return !!session;
}

export async function addContact(
  ownerId: string,
  username: string,
  publicKey?: Uint8Array,
  deviceId?: string,
  contactUserId?: string,
) {
  const trimmed = username.trim();
  if (!trimmed) {
    throw new Error('Contact username is required.');
  }

  await homyDb.runAsync(
    'INSERT OR REPLACE INTO contacts (id, owner_id, contact_user_id, username, public_key, device_id, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [
      `contact_${Date.now()}_${Math.random().toString(16).slice(2)}`,
      ownerId,
      contactUserId ?? null,
      trimmed,
      publicKey ? Uint8Array.from(publicKey) : null,
      deviceId ?? null,
      'active',
      new Date().toISOString(),
    ],
  );

  return { username: trimmed };
}

export async function listContacts(ownerId: string) {
  return homyDb.getAllAsync(
    'SELECT * FROM contacts WHERE owner_id = ? ORDER BY created_at DESC',
    [ownerId],
  );
}

async function ensureSelfContact(ownerId: string) {
  const profile = await homyDb.getFirstAsync<{ username: string }>(
    'SELECT username FROM users WHERE id = ?',
    [ownerId],
  );
  if (!profile) {
    throw new Error('Your local account could not be found.');
  }

  const identity = await getOrCreateIdentityKeys();
  const deviceId = (await SecureStore.getItemAsync(DEVICE_ID_KEY)) ?? generateDeviceId();
  await SecureStore.setItemAsync(DEVICE_ID_KEY, deviceId);
  await addContact(ownerId, profile.username, identity.publicKey, deviceId, ownerId);
}

export type FriendRequestRecord = {
  id: string;
  requester_id: string;
  recipient_id: string;
  requester_username: string;
  recipient_username: string;
  status: 'pending' | 'accepted' | 'rejected';
  created_at: string;
  responded_at: string | null;
};

async function findRemoteUserByUsername(usernameValue: string) {
  if (!supabase) {
    throw new Error('Supabase is not configured.');
  }

  const username = usernameValue.trim();
  const { data, error } = await supabase
    .from('users')
    .select('id, username')
    .eq('username', username)
    .maybeSingle();

  if (error) {
    throw new Error(error.message);
  }

  if (!data) {
    throw new Error('No account uses that exact username.');
  }

  return { userId: String(data.id), username: String(data.username) };
}

async function findFriendRequestBetween(firstUserId: string, secondUserId: string) {
  if (!supabase) {
    return null;
  }

  const { data, error } = await supabase
    .from('friend_requests')
    .select('id, requester_id, recipient_id, status')
    .eq('requester_id', firstUserId)
    .eq('recipient_id', secondUserId)
    .maybeSingle();

  if (error) {
    throw new Error(error.message);
  }

  if (data) {
    return data;
  }

  const reverse = await supabase
    .from('friend_requests')
    .select('id, requester_id, recipient_id, status')
    .eq('requester_id', secondUserId)
    .eq('recipient_id', firstUserId)
    .maybeSingle();

  if (reverse.error) {
    throw new Error(reverse.error.message);
  }

  return reverse.data;
}

export async function sendFriendRequest(ownerId: string, usernameValue: string) {
  const target = await findRemoteUserByUsername(usernameValue);

  if (target.userId === ownerId) {
    throw new Error('You cannot send a friend request to yourself.');
  }

  const existing = await findFriendRequestBetween(ownerId, target.userId);
  if (existing?.status === 'accepted') {
    throw new Error('You are already friends with this user.');
  }
  if (existing?.status === 'pending') {
    throw new Error('A friend request is already pending.');
  }

  const owner = await homyDb.getFirstAsync<{ username: string }>(
    'SELECT username FROM users WHERE id = ?',
    [ownerId],
  );
  if (!owner) {
    throw new Error('Your local account could not be found.');
  }

  const request = {
    id: `request_${Date.now()}_${bytesToHex(nacl.randomBytes(6))}`,
    requester_id: ownerId,
    recipient_id: target.userId,
    requester_username: owner.username,
    recipient_username: target.username,
    status: 'pending' as const,
    created_at: new Date().toISOString(),
  };

  if (supabase) {
    const isResubmission = existing?.status === 'rejected' && existing.requester_id === ownerId;
    const result = isResubmission
      ? await supabase
        .from('friend_requests')
        .update({ status: 'pending', responded_at: null, created_at: request.created_at })
        .eq('id', existing.id)
      : await supabase.from('friend_requests').insert({
        id: request.id,
        requester_id: request.requester_id,
        recipient_id: request.recipient_id,
        status: request.status,
        created_at: request.created_at,
      });
    const error = result.error;
    if (error) {
      throw new Error(error.message);
    }
  }

  await homyDb.runAsync(
    'INSERT OR REPLACE INTO friend_requests (id, requester_id, recipient_id, requester_username, recipient_username, status, created_at, responded_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)',
    [
      existing?.status === 'rejected' && existing.requester_id === ownerId ? existing.id : request.id,
      request.requester_id,
      request.recipient_id,
      owner.username,
      target.username,
      request.status,
      request.created_at,
    ],
  );

  return request;
}

export async function listIncomingFriendRequests(ownerId: string) {
  if (!supabase) {
    return homyDb.getAllAsync<FriendRequestRecord>(
      'SELECT * FROM friend_requests WHERE recipient_id = ? AND status = ? ORDER BY created_at DESC',
      [ownerId, 'pending'],
    );
  }

  const { data, error } = await supabase
    .from('friend_requests')
    .select('id, requester_id, recipient_id, status, created_at, responded_at')
    .eq('recipient_id', ownerId)
    .eq('status', 'pending')
    .order('created_at', { ascending: false });

  if (error) {
    throw new Error(error.message);
  }

  const requesterIds = (data ?? []).map((row) => String(row.requester_id));
  const users = requesterIds.length === 0
    ? []
    : (await supabase.from('users').select('id, username').in('id', requesterIds)).data ?? [];

  return (data ?? []).map((row) => ({
    ...row,
    requester_username: users.find((user) => user.id === row.requester_id)?.username ?? 'Unknown user',
    recipient_username: '',
  })) as FriendRequestRecord[];
}

export async function respondToFriendRequest(ownerId: string, requestId: string, accept: boolean) {
  if (!supabase) {
    throw new Error('Supabase is required to respond to friend requests.');
  }

  const { data: request, error: requestError } = await supabase
    .from('friend_requests')
    .select('id, requester_id, recipient_id, status')
    .eq('id', requestId)
    .eq('recipient_id', ownerId)
    .maybeSingle();

  if (requestError) {
    throw new Error(requestError.message);
  }
  if (!request) {
    throw new Error('Friend request not found.');
  }
  if (request.status !== 'pending') {
    throw new Error('This friend request has already been handled.');
  }

  const nextStatus = accept ? 'accepted' : 'rejected';
  const { error } = await supabase
    .from('friend_requests')
    .update({ status: nextStatus, responded_at: new Date().toISOString() })
    .eq('id', requestId)
    .eq('recipient_id', ownerId)
    .eq('status', 'pending');

  if (error) {
    throw new Error(error.message);
  }

  return nextStatus;
}

export async function syncAcceptedContacts(ownerId: string) {
  if (!supabase) {
    await ensureSelfContact(ownerId);
    return listContacts(ownerId);
  }

  const { data, error } = await supabase
    .from('friend_requests')
    .select('requester_id, recipient_id')
    .eq('status', 'accepted')
    .or(`requester_id.eq.${ownerId},recipient_id.eq.${ownerId}`);

  if (error) {
    throw new Error(error.message);
  }

  const peerIds = (data ?? []).map((row) => (
    String(row.requester_id) === ownerId ? String(row.recipient_id) : String(row.requester_id)
  ));
  if (peerIds.length === 0) {
    await ensureSelfContact(ownerId);
    return listContacts(ownerId);
  }

  const { data: users, error: usersError } = await supabase
    .from('users')
    .select('id, username')
    .in('id', peerIds);
  if (usersError) {
    throw new Error(usersError.message);
  }

  for (const user of users ?? []) {
    try {
      const bundle = await fetchRemoteContactBundle(String(user.username));
      await addContact(ownerId, bundle.username, bundle.identityPublicKey, bundle.deviceId, bundle.userId);
    } catch {
      await addContact(ownerId, String(user.username), undefined, undefined, String(user.id));
    }
  }

  await ensureSelfContact(ownerId);
  return listContacts(ownerId);
}

export async function isAcceptedFriend(ownerId: string, peerUserId: string) {
  const request = await findFriendRequestBetween(ownerId, peerUserId);
  return request?.status === 'accepted';
}

async function requireAcceptedFriend(ownerId: string, peerUsername: string) {
  const localProfile = await homyDb.getFirstAsync<{ username: string }>(
    'SELECT username FROM users WHERE id = ?',
    [ownerId],
  );
  if (localProfile?.username === peerUsername.trim()) {
    return {
      userId: ownerId,
      username: localProfile.username,
      deviceId: '',
      identityPublicKey: new Uint8Array(),
      prekeyId: '',
      prekeyPublicKey: new Uint8Array(),
    };
  }

  const peer = await fetchRemoteContactBundle(peerUsername);
  if (!(await isAcceptedFriend(ownerId, peer.userId))) {
    throw new Error('Accept the friend request before starting a conversation.');
  }
  return peer;
}

async function ensureSelfRatchetSession(ownerUserId: string, peerUsername: string) {
  const existing = await getRatchetSession(ownerUserId, ownerUserId);
  if (existing) {
    return {
      peerUserId: ownerUserId,
      peerUsername,
      rootKey: Uint8Array.from(existing.root_key),
      peerDeviceId: existing.peer_device_id ?? '',
      peerPrekeyId: existing.peer_prekey_id ?? 'self',
      myEphemeralPublicKey: Uint8Array.from(existing.my_ephemeral_public_key),
    };
  }

  const identity = await getOrCreateIdentityKeys();
  const deviceId = (await SecureStore.getItemAsync(DEVICE_ID_KEY)) ?? generateDeviceId();
  await SecureStore.setItemAsync(DEVICE_ID_KEY, deviceId);
  const rootKey = nacl.hash(concatBytes([
    identity.privateKey,
    textEncoder.encode('Homy self-chat v1'),
  ])).slice(0, 32);

  await saveRatchetSession({
    ownerUserId,
    peerUserId: ownerUserId,
    peerUsername,
    peerDeviceId: deviceId,
    peerPrekeyId: 'self',
    rootKey,
    myEphemeralPublicKey: identity.publicKey,
    myEphemeralSecretKey: identity.privateKey,
  });

  return {
    peerUserId: ownerUserId,
    peerUsername,
    rootKey,
    peerDeviceId: deviceId,
    peerPrekeyId: 'self',
    myEphemeralPublicKey: identity.publicKey,
  };
}

async function getRatchetSession(ownerUserId: string, peerUserId: string) {
  const row: {
    id: string;
    owner_id: string;
    peer_user_id: string;
    peer_username: string;
    peer_device_id: string | null;
    peer_prekey_id: string | null;
    root_key: Uint8Array;
    my_ephemeral_public_key: Uint8Array;
    my_ephemeral_secret_key: Uint8Array;
    created_at: string;
    updated_at: string;
  } | null = await homyDb.getFirstAsync(
    'SELECT * FROM ratchet_sessions WHERE owner_id = ? AND peer_user_id = ?',
    [ownerUserId, peerUserId],
  );

  return row;
}

async function saveRatchetSession(input: {
  ownerUserId: string;
  peerUserId: string;
  peerUsername: string;
  peerDeviceId: string;
  peerPrekeyId: string;
  rootKey: Uint8Array;
  myEphemeralPublicKey: Uint8Array;
  myEphemeralSecretKey: Uint8Array;
}) {
  const now = new Date().toISOString();

  await homyDb.runAsync(
    `INSERT OR REPLACE INTO ratchet_sessions
      (id, owner_id, peer_user_id, peer_username, peer_device_id, peer_prekey_id, root_key, my_ephemeral_public_key, my_ephemeral_secret_key, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT created_at FROM ratchet_sessions WHERE owner_id = ? AND peer_user_id = ?), ?), ?)`,
    [
      `session_${input.ownerUserId}_${input.peerUserId}`,
      input.ownerUserId,
      input.peerUserId,
      input.peerUsername,
      input.peerDeviceId,
      input.peerPrekeyId,
      Uint8Array.from(input.rootKey),
      Uint8Array.from(input.myEphemeralPublicKey),
      Uint8Array.from(input.myEphemeralSecretKey),
      input.ownerUserId,
      input.peerUserId,
      now,
      now,
    ],
  );
}

async function ensureRatchetSession(ownerUserId: string, peerUsername: string) {
  const localProfile = await homyDb.getFirstAsync<{ username: string }>(
    'SELECT username FROM users WHERE id = ?',
    [ownerUserId],
  );
  if (localProfile?.username === peerUsername.trim()) {
    return ensureSelfRatchetSession(ownerUserId, localProfile.username);
  }

  const bundle = await requireAcceptedFriend(ownerUserId, peerUsername);
  const existing = await getRatchetSession(ownerUserId, bundle.userId);

  if (existing) {
    return {
      peerUserId: bundle.userId,
      peerUsername: bundle.username,
      rootKey: Uint8Array.from(existing.root_key),
      peerDeviceId: existing.peer_device_id ?? bundle.deviceId,
      peerPrekeyId: existing.peer_prekey_id ?? bundle.prekeyId,
      myEphemeralPublicKey: Uint8Array.from(existing.my_ephemeral_public_key),
    };
  }

  const created = await deriveX3DHSharedSecret(ownerUserId, peerUsername);
  await saveRatchetSession({
    ownerUserId,
    peerUserId: created.peerUserId,
    peerUsername: created.peerUsername,
    peerDeviceId: created.peerDeviceId,
    peerPrekeyId: created.peerPrekeyId,
    rootKey: created.rootKey,
    myEphemeralPublicKey: created.myEphemeralPublicKey,
    myEphemeralSecretKey: created.myEphemeralSecretKey,
  });

  return {
    peerUserId: created.peerUserId,
    peerUsername: created.peerUsername,
    rootKey: created.rootKey,
    peerDeviceId: created.peerDeviceId,
    peerPrekeyId: created.peerPrekeyId,
    myEphemeralPublicKey: created.myEphemeralPublicKey,
  };
}

async function fetchRemoteIdentityPublicKeyByUserId(userId: string) {
  if (!supabase) {
    throw new Error('Supabase is not configured.');
  }

  const { data, error } = await supabase
    .from('public_keys')
    .select('public_key, created_at')
    .eq('user_id', userId)
    .order('created_at', { ascending: false })
    .limit(1);

  if (error) {
    throw new Error(error.message);
  }

  const row = data?.[0];
  if (!row?.public_key) {
    throw new Error('Sender identity key not found.');
  }

  return decodeBytesFromPostgresBytea(String(row.public_key));
}

function getConversationId(userA: string, userB: string) {
  const [left, right] = [userA, userB].sort();
  return `conv_${left}_${right}`;
}

export async function setPresence(userId: string, status: 'online' | 'offline') {
  const now = new Date().toISOString();

  await homyDb.runAsync(
    'INSERT OR REPLACE INTO presence (user_id, status, last_seen_at) VALUES (?, ?, ?)',
    [userId, status, now],
  );

  if (supabase) {
    const { error } = await supabase
      .from('presence')
      .upsert({ user_id: userId, status, last_seen_at: now }, { onConflict: 'user_id' });

    if (error) {
      throw new Error(error.message);
    }
  }
}

export async function getPeerPresence(ownerId: string, peerUsername: string) {
  const bundle = await requireAcceptedFriend(ownerId, peerUsername);

  if (!supabase) {
    return { status: 'unknown', lastSeenAt: null as string | null };
  }

  const { data, error } = await supabase
    .from('presence')
    .select('status, last_seen_at')
    .eq('user_id', bundle.userId)
    .maybeSingle();

  if (error) {
    throw new Error(error.message);
  }

  return {
    status: (data?.status as string | undefined) ?? 'offline',
    lastSeenAt: (data?.last_seen_at as string | undefined) ?? null,
  };
}

export async function setTypingState(ownerUserId: string, peerUsername: string, isTyping: boolean) {
  const peer = await requireAcceptedFriend(ownerUserId, peerUsername);
  const conversationId = getConversationId(ownerUserId, peer.userId);
  const now = new Date().toISOString();
  const typingId = `typing_${conversationId}_${ownerUserId}`;

  await homyDb.runAsync(
    'INSERT OR REPLACE INTO typing_events (id, conversation_id, user_id, is_typing, updated_at) VALUES (?, ?, ?, ?, ?)',
    [typingId, conversationId, ownerUserId, isTyping ? 1 : 0, now],
  );

  if (supabase) {
    const { error } = await supabase
      .from('typing_events')
      .upsert(
        {
          id: typingId,
          conversation_id: conversationId,
          user_id: ownerUserId,
          is_typing: isTyping,
          updated_at: now,
        },
        { onConflict: 'id' },
      );

    if (error) {
      throw new Error(error.message);
    }
  }
}

export async function getPeerTypingState(ownerUserId: string, peerUsername: string) {
  const peer = await requireAcceptedFriend(ownerUserId, peerUsername);
  const conversationId = getConversationId(ownerUserId, peer.userId);

  if (!supabase) {
    return false;
  }

  const { data, error } = await supabase
    .from('typing_events')
    .select('is_typing, updated_at')
    .eq('conversation_id', conversationId)
    .eq('user_id', peer.userId)
    .maybeSingle();

  if (error) {
    throw new Error(error.message);
  }

  return Boolean(data?.is_typing);
}

export async function markConversationRead(ownerUserId: string, peerUsername: string) {
  if (!supabase) {
    return;
  }

  const peer = await fetchRemoteContactBundle(peerUsername);
  const conversationId = getConversationId(ownerUserId, peer.userId);
  const { data, error } = await supabase
    .from('messages')
    .select('id')
    .eq('conversation_id', conversationId)
    .eq('recipient_id', ownerUserId)
    .order('sent_at', { ascending: true })
    .limit(200);

  if (error) {
    throw new Error(error.message);
  }

  const now = new Date().toISOString();
  const payload = (data ?? []).map((row) => ({
    id: `rr_${row.id}_${ownerUserId}`,
    message_id: String(row.id),
    user_id: ownerUserId,
    read_at: now,
  }));

  if (payload.length === 0) {
    return;
  }

  const { error: upsertError } = await supabase.from('read_receipts').upsert(payload, { onConflict: 'id' });
  if (upsertError) {
    throw new Error(upsertError.message);
  }
}

export async function getReadReceiptSummary(ownerUserId: string, peerUsername: string) {
  if (!supabase) {
    return { peerReadCount: 0 };
  }

  const peer = await requireAcceptedFriend(ownerUserId, peerUsername);
  const conversationId = getConversationId(ownerUserId, peer.userId);
  const { data, error } = await supabase
    .from('messages')
    .select('id, sender_id')
    .eq('conversation_id', conversationId)
    .eq('sender_id', ownerUserId)
    .order('sent_at', { ascending: true })
    .limit(200);

  if (error) {
    throw new Error(error.message);
  }

  const sentMessageIds = (data ?? []).map((row) => String(row.id));
  if (sentMessageIds.length === 0) {
    return { peerReadCount: 0 };
  }

  const { data: reads, error: readsError } = await supabase
    .from('read_receipts')
    .select('message_id')
    .eq('user_id', peer.userId)
    .in('message_id', sentMessageIds);

  if (readsError) {
    throw new Error(readsError.message);
  }

  return {
    peerReadCount: (reads ?? []).length,
  };
}

export async function sendEncryptedMessage(ownerUserId: string, peerUsername: string, plaintextValue: string) {
  const plaintext = plaintextValue.trim();
  if (!plaintext) {
    throw new Error('Message is empty.');
  }

  const session = await ensureRatchetSession(ownerUserId, peerUsername);
  const conversationId = getConversationId(ownerUserId, session.peerUserId);
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  const ciphertext = nacl.secretbox(textEncoder.encode(plaintext), nonce, session.rootKey);
  const now = new Date().toISOString();
  const messageId = `msg_${Date.now()}_${Math.random().toString(16).slice(2)}`;

  await homyDb.runAsync(
    'INSERT OR REPLACE INTO conversations (id, user_a, user_b, last_message, updated_at) VALUES (?, ?, ?, ?, ?)',
    [conversationId, ownerUserId, session.peerUserId, '[encrypted]', now],
  );

  await homyDb.runAsync(
    'INSERT INTO messages (id, conversation_id, sender_id, recipient_id, ciphertext, nonce, x3dh_ephemeral_public_key, x3dh_prekey_id, sent_at, disappearing_mode) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [
      messageId,
      conversationId,
      ownerUserId,
      session.peerUserId,
      Uint8Array.from(ciphertext),
      Uint8Array.from(nonce),
      Uint8Array.from(session.myEphemeralPublicKey),
      session.peerPrekeyId,
      now,
      'off',
    ],
  );

  if (supabase) {
    const conversationPayload = {
      id: conversationId,
      user_a: ownerUserId,
      user_b: session.peerUserId,
      last_message: '[encrypted]',
      updated_at: now,
    };

    const { error: conversationError } = await supabase
      .from('conversations')
      .upsert(conversationPayload, { onConflict: 'id' });

    if (conversationError) {
      throw new Error(conversationError.message);
    }

    const messagePayload = {
      id: messageId,
      conversation_id: conversationId,
      sender_id: ownerUserId,
      recipient_id: session.peerUserId,
      ciphertext: encodeBytesForPostgresBytea(ciphertext),
      nonce: encodeBytesForPostgresBytea(nonce),
      x3dh_ephemeral_public_key: encodeBytesForPostgresBytea(session.myEphemeralPublicKey),
      x3dh_prekey_id: session.peerPrekeyId,
      sent_at: now,
      disappearing_mode: 'off',
    };

    const { error: messageError } = await supabase.from('messages').insert(messagePayload);
    if (messageError) {
      throw new Error(messageError.message);
    }
  }

  await setTypingState(ownerUserId, peerUsername, false);

  return {
    id: messageId,
    conversationId,
    sentAt: now,
  };
}

async function syncStoredSelfMessages(ownerUserId: string, peerUsername: string) {
  const session = await ensureSelfRatchetSession(ownerUserId, peerUsername);
  const conversationId = getConversationId(ownerUserId, ownerUserId);
  const rows = await homyDb.getAllAsync<{
    id: string;
    sender_id: string;
    ciphertext: Uint8Array;
    nonce: Uint8Array;
    sent_at: string;
  }>(
    'SELECT id, sender_id, ciphertext, nonce, sent_at FROM messages WHERE conversation_id = ? ORDER BY sent_at ASC',
    [conversationId],
  );

  return rows.map((row) => {
    const opened = nacl.secretbox.open(
      Uint8Array.from(row.ciphertext),
      Uint8Array.from(row.nonce),
      session.rootKey,
    );

    return {
      id: row.id,
      senderId: row.sender_id,
      text: opened ? textDecoder.decode(opened) : '[unable to decrypt]',
      sentAt: row.sent_at,
    };
  });
}

export async function syncAndDecryptMessages(ownerUserId: string, peerUsername: string) {
  if (!supabase) {
    const localProfile = await homyDb.getFirstAsync<{ username: string }>(
      'SELECT username FROM users WHERE id = ?',
      [ownerUserId],
    );
    if (localProfile?.username === peerUsername.trim()) {
      return syncStoredSelfMessages(ownerUserId, localProfile.username);
    }
    return [] as Array<{ id: string; senderId: string; text: string; sentAt: string }>;
  }

  const peerBundle = await fetchRemoteContactBundle(peerUsername);
  const conversationId = getConversationId(ownerUserId, peerBundle.userId);
  const senderSession = await ensureRatchetSession(ownerUserId, peerUsername);
  const identity = await getOrCreateIdentityKeys();
  const privatePrekeyMap = await getStoredPrekeyPrivateMap();

  const { data, error } = await supabase
    .from('messages')
    .select('id, sender_id, recipient_id, ciphertext, nonce, x3dh_ephemeral_public_key, x3dh_prekey_id, sent_at, disappearing_mode')
    .eq('conversation_id', conversationId)
    .order('sent_at', { ascending: true })
    .limit(200);

  if (error) {
    throw new Error(error.message);
  }

  const decrypted: Array<{ id: string; senderId: string; text: string; sentAt: string }> = [];

  for (const row of data ?? []) {
    const ciphertext = decodeBytesFromPostgresBytea(String(row.ciphertext));
    const nonce = decodeBytesFromPostgresBytea(String(row.nonce));
    let opened: Uint8Array | null = null;

    if (String(row.sender_id) === ownerUserId) {
      opened = nacl.secretbox.open(ciphertext, nonce, senderSession.rootKey);
    } else {
      const prekeyId = String(row.x3dh_prekey_id ?? '');
      const senderEphemeralRaw = String(row.x3dh_ephemeral_public_key ?? '');
      const prekeyPrivateKey = prekeyId ? getPrekeyPrivateKeyFromMap(privatePrekeyMap, prekeyId) : null;

      if (prekeyPrivateKey && senderEphemeralRaw) {
        const senderIdentityPublicKey = await fetchRemoteIdentityPublicKeyByUserId(String(row.sender_id));
        const senderEphemeralPublicKey = decodeBytesFromPostgresBytea(senderEphemeralRaw);
        const responderKey = deriveResponderSharedSecret(
          identity.privateKey,
          prekeyPrivateKey,
          senderIdentityPublicKey,
          senderEphemeralPublicKey,
        );
        opened = nacl.secretbox.open(ciphertext, nonce, responderKey);
      }
    }

    const text = opened ? textDecoder.decode(opened) : '[unable to decrypt]';

    const existing: { id: string } | null = await homyDb.getFirstAsync(
      'SELECT id FROM messages WHERE id = ?',
      [row.id],
    );

    if (!existing) {
      await homyDb.runAsync(
        'INSERT INTO messages (id, conversation_id, sender_id, recipient_id, ciphertext, nonce, x3dh_ephemeral_public_key, x3dh_prekey_id, sent_at, disappearing_mode) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [
          String(row.id),
          conversationId,
          String(row.sender_id),
          String(row.recipient_id),
          Uint8Array.from(ciphertext),
          Uint8Array.from(nonce),
          row.x3dh_ephemeral_public_key ? decodeBytesFromPostgresBytea(String(row.x3dh_ephemeral_public_key)) : null,
          row.x3dh_prekey_id ? String(row.x3dh_prekey_id) : null,
          String(row.sent_at),
          String(row.disappearing_mode ?? 'off'),
        ],
      );
    }

    decrypted.push({
      id: String(row.id),
      senderId: String(row.sender_id),
      text,
      sentAt: String(row.sent_at),
    });
  }

  await markConversationRead(ownerUserId, peerUsername);

  return decrypted;
}

export function subscribeToConversationMessages(
  ownerUserId: string,
  peerUserId: string,
  onMessage: () => void,
) {
  if (!supabase) {
    return () => undefined;
  }

  const conversationId = getConversationId(ownerUserId, peerUserId);
  const channel = supabase
    .channel(`conversation:${conversationId}`)
    .on(
      'postgres_changes',
      {
        event: '*',
        schema: 'public',
        table: 'messages',
        filter: `conversation_id=eq.${conversationId}`,
      },
      () => onMessage(),
    )
    .subscribe();

  return () => {
    void supabase.removeChannel(channel);
  };
}

export async function registerLocalUser(usernameValue: string, passwordValue: string, pinValue: string) {
  const trimmedUsername = usernameValue.trim();
  const passwordHash = hashSecret(passwordValue);
  const pinHash = hashSecret(pinValue);
  const recoveryPhrase = generateRecoveryPhrase();
  const now = new Date().toISOString();

  if (trimmedUsername.length < 3 || trimmedUsername.length > 20) {
    throw new Error('Username must be 3 to 20 characters.');
  }

  const duplicate = await homyDb.getAllAsync('SELECT id FROM users WHERE username = ?', [trimmedUsername]);
  if (duplicate.length > 0) {
    throw new Error('Username already taken.');
  }

  const userId = `user_${Date.now()}_${Math.random().toString(16).slice(2)}`;
  const deviceId = (await SecureStore.getItemAsync(DEVICE_ID_KEY)) ?? generateDeviceId();
  const identity = await getOrCreateIdentityKeys();

  await SecureStore.setItemAsync(DEVICE_ID_KEY, deviceId);
  await homyDb.runAsync(
    'INSERT INTO users (id, username, password_hash, recovery_phrase, pin_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [userId, trimmedUsername, passwordHash, recoveryPhrase, pinHash, now, now],
  );
  await homyDb.runAsync(
    'INSERT INTO public_keys (id, user_id, device_id, public_key, created_at) VALUES (?, ?, ?, ?, ?)',
    [`pk_${Date.now()}`, userId, deviceId, Uint8Array.from(identity.publicKey), now],
  );

  const prekeys = await generateAndStorePrekeys(userId, 10);

  if (supabase) {
    const remotePayload = {
      id: userId,
      username: trimmedUsername,
      created_at: now,
      updated_at: now,
      last_seen_at: now,
    };

    const { error } = await supabase.from('users').upsert(remotePayload, { onConflict: 'id' });
    if (error) {
      throw new Error(error.message);
    }

    await upsertRemoteIdentityPublicKey(userId, deviceId, identity.publicKey, now);
    await publishPrekeysRemote(userId, prekeys, now);
  }

  await saveSession(userId, trimmedUsername);
  await setPresence(userId, 'online');

  return {
    userId,
    username: trimmedUsername,
    recoveryPhrase,
    deviceId,
    publicKey: Uint8Array.from(identity.publicKey),
  };
}

export async function loginLocalUser(usernameValue: string, passwordValue: string, pinValue: string) {
  const trimmedUsername = usernameValue.trim();
  const passwordHash = hashSecret(passwordValue);
  const pinHash = hashSecret(pinValue);

  const match: {
    id: string;
    username: string;
    password_hash: string;
    recovery_phrase: string;
    pin_hash: string;
    created_at: string;
    updated_at: string;
  } | null = await homyDb.getFirstAsync(
    'SELECT * FROM users WHERE username = ? AND password_hash = ? AND pin_hash = ?',
    [trimmedUsername, passwordHash, pinHash],
  );

  if (!match) {
    throw new Error('Incorrect username, password, or PIN.');
  }

  await saveSession(match.id, match.username);
  await setPresence(match.id, 'online');
  return match;
}

export async function getUserProfile(userId: string) {
  const row = await homyDb.getFirstAsync<{ username: string; profile_bio: string }>(
    'SELECT username, profile_bio FROM users WHERE id = ?',
    [userId],
  );
  if (!row) {
    throw new Error('Profile not found.');
  }
  return row;
}

export async function updateUserProfile(userId: string, profileBioValue: string) {
  const profileBio = profileBioValue.trim().slice(0, 160);
  await homyDb.runAsync(
    'UPDATE users SET profile_bio = ?, updated_at = ? WHERE id = ?',
    [profileBio, new Date().toISOString(), userId],
  );
  return getUserProfile(userId);
}

export async function getSupabaseStatus() {
  if (!supabase) {
    return { connected: false, error: 'Missing EXPO_PUBLIC_SUPABASE_URL or EXPO_PUBLIC_SUPABASE_ANON_KEY' };
  }

  const { data, error } = await supabase.from('users').select('username').limit(1);

  if (error) {
    return { connected: false, error: error.message };
  }

  return {
    connected: true,
    rows: data ?? [],
  };
}
