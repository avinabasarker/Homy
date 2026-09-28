import { BlurView } from 'expo-blur';
import { useFonts } from 'expo-font';
import { Inter_400Regular, Inter_500Medium, Inter_600SemiBold, Inter_700Bold } from '@expo-google-fonts/inter';
import { useEffect, useRef, useState } from 'react';
import {
  Alert,
  AppState,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import { StatusBar } from 'expo-status-bar';
import { SafeAreaView } from 'react-native-safe-area-context';

import {
  clearSession,
  getStoredSession,
  getSupabaseStatus,
  getPeerPresence,
  getUserProfile,
  getPeerTypingState,
  getReadReceiptSummary,
  hashSecret,
  homyDb,
  initializeLocalDatabase,
  listIncomingFriendRequests,
  loginLocalUser,
  respondToFriendRequest,
  registerLocalUser,
  sendFriendRequest,
  setPresence,
  setTypingState,
  sendEncryptedMessage,
  subscribeToConversationMessages,
  syncAcceptedContacts,
  syncAndDecryptMessages,
  updateUserProfile,
} from './lib/homyCore';

type AuthMode = 'signup' | 'login';
type ScreenState = 'auth' | 'pin' | 'dashboard';
type DashboardTab = 'chats' | 'settings';

type SessionUser = {
  userId: string;
  username: string;
};

type ContactRecord = {
  id: string;
  owner_id: string;
  contact_user_id: string | null;
  username: string;
  public_key: Uint8Array | null;
  device_id: string | null;
  status: string;
  created_at: string;
};

type FriendRequest = {
  id: string;
  requester_id: string;
  requester_username: string;
  status: 'pending' | 'accepted' | 'rejected';
  created_at: string;
};

type DecryptedMessage = {
  id: string;
  senderId: string;
  text: string;
  sentAt: string;
};

export default function App() {
  const [mode, setMode] = useState<AuthMode>('signup');
  const [screen, setScreen] = useState<ScreenState>('auth');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [pin, setPin] = useState('');
  const [sessionUser, setSessionUser] = useState<SessionUser | null>(null);
  const [contacts, setContacts] = useState<ContactRecord[]>([]);
  const [incomingRequests, setIncomingRequests] = useState<FriendRequest[]>([]);
  const [profileBio, setProfileBio] = useState('');
  const [contactUsername, setContactUsername] = useState('');
  const [activePeer, setActivePeer] = useState('');
  const [draftMessage, setDraftMessage] = useState('');
  const [messages, setMessages] = useState<DecryptedMessage[]>([]);
  const [isPeerTyping, setIsPeerTyping] = useState(false);
  const [peerPresence, setPeerPresence] = useState('unknown');
  const [peerReadCount, setPeerReadCount] = useState(0);
  const [dashboardTab, setDashboardTab] = useState<DashboardTab>('chats');
  const [status, setStatus] = useState('Booting Homy...');
  const [isBooting, setIsBooting] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isBackgrounded, setIsBackgrounded] = useState(false);
  const typingTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const [fontsLoaded] = useFonts({
    Inter_400Regular,
    Inter_500Medium,
    Inter_600SemiBold,
    Inter_700Bold,
  });

  useEffect(() => {
    let active = true;

    const init = async () => {
      try {
        await initializeLocalDatabase();

        const stored = await getStoredSession();
        const result = await getSupabaseStatus();

        if (!active) return;

        if (stored) {
          setSessionUser({ userId: stored.userId, username: stored.username });
          setScreen('pin');
          setStatus('Session found. Enter your PIN to unlock.');
        } else if (result.connected) {
          setStatus('Supabase connected. Session ready.');
          setScreen('auth');
        } else {
          setStatus('Local database ready. Add Supabase secrets to continue.');
          setScreen('auth');
        }
      } catch (error) {
        if (active) {
          setStatus('Database boot failed. Please check your environment.');
        }
      } finally {
        if (active) {
          setIsBooting(false);
        }
      }
    };

    init();

    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    const subscription = AppState.addEventListener('change', (nextState) => {
      const backgrounded = nextState !== 'active';
      setIsBackgrounded(backgrounded);

      if (backgrounded && sessionUser && screen === 'dashboard') {
        setScreen('pin');
        setPin('');
        setStatus('Session locked. Enter your PIN to continue.');
      }
    });

    return () => subscription.remove();
  }, [screen, sessionUser]);

  const refreshContacts = async (ownerId: string) => {
    const rows = await syncAcceptedContacts(ownerId) as ContactRecord[];
    setContacts(rows);

    if (rows.length > 0 && !activePeer) {
      setActivePeer(rows[0].username);
    }
  };

  const refreshFriendRequests = async (ownerId: string) => {
    const rows = await listIncomingFriendRequests(ownerId) as FriendRequest[];
    setIncomingRequests(rows);
  };

  const refreshConversationMeta = async (ownerId: string, peer: string) => {
    if (!peer) {
      return;
    }

    const [typing, presence, reads] = await Promise.all([
      getPeerTypingState(ownerId, peer),
      getPeerPresence(ownerId, peer),
      getReadReceiptSummary(ownerId, peer),
    ]);

    setIsPeerTyping(typing);
    setPeerPresence(presence.status);
    setPeerReadCount(reads.peerReadCount);
  };

  const refreshProfile = async (ownerId: string) => {
    const profile = await getUserProfile(ownerId);
    setProfileBio(profile.profile_bio);
  };

  useEffect(() => {
    if (!sessionUser || !activePeer || screen !== 'dashboard') {
      return;
    }

    const refresh = async () => {
      try {
        const synced = await syncAndDecryptMessages(sessionUser.userId, activePeer);
        setMessages(synced);
        await refreshConversationMeta(sessionUser.userId, activePeer);
      } catch {
        // Realtime refresh is best-effort while connectivity changes.
      }
    };

    void refresh();
    const contact = contacts.find((item) => item.username === activePeer);
    const unsubscribe = contact?.contact_user_id
      ? subscribeToConversationMessages(sessionUser.userId, contact.contact_user_id, () => {
          void refresh();
        })
      : () => undefined;

    return () => {
      unsubscribe();
    };
  }, [sessionUser, activePeer, screen, contacts]);

  useEffect(() => {
    if (!sessionUser || screen !== 'dashboard') {
      return;
    }

    const refreshSocialState = async () => {
      try {
        await refreshFriendRequests(sessionUser.userId);
        await refreshContacts(sessionUser.userId);
      } catch {
        // Request refresh is best-effort while connectivity changes.
      }
    };

    void refreshSocialState();
    const timer = setInterval(() => {
      void refreshSocialState();
    }, 5000);

    return () => clearInterval(timer);
  }, [sessionUser, screen]);

  const canSubmit = username.trim().length >= 3 && password.length > 0 && pin.length >= 4;

  const handleSubmit = async () => {
    if (!canSubmit) {
      Alert.alert('Missing details', 'Use a username, password, and 4-digit PIN.');
      return;
    }

    setIsSubmitting(true);
    setStatus(mode === 'signup' ? 'Creating secure profile...' : 'Checking credentials...');

    try {
      if (mode === 'signup') {
        const result = await registerLocalUser(username, password, pin);
        setSessionUser({ userId: result.userId, username: result.username });
        await refreshContacts(result.userId);
        await refreshFriendRequests(result.userId);
        await refreshProfile(result.userId);
        setDashboardTab('chats');
        setScreen('dashboard');
        setStatus(`Profile ready. Seed: ${result.recoveryPhrase}`);
        Alert.alert('Account created', `Recovery phrase: ${result.recoveryPhrase}`);
      } else {
        const result = await loginLocalUser(username, password, pin);
        setSessionUser({ userId: result.id, username: result.username });
        await refreshContacts(result.id);
        await refreshFriendRequests(result.id);
        await refreshProfile(result.id);
        setDashboardTab('chats');
        setScreen('dashboard');
        setStatus(`Welcome back, ${result.username}.`);
        Alert.alert('Login successful', `Signed in as ${result.username}`);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Please try again.';
      setStatus(message);
      Alert.alert('Authentication failed', message);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleUnlock = async () => {
    if (!sessionUser || pin.length < 4) {
      Alert.alert('PIN required', 'Enter your 4-digit PIN to unlock.');
      return;
    }

    const match = await homyDb.getFirstAsync(
      'SELECT id, username FROM users WHERE username = ? AND pin_hash = ?',
      [sessionUser.username, hashSecret(pin)],
    );

    if (!match) {
      Alert.alert('Unlock failed', 'This PIN is incorrect.');
      setStatus('PIN mismatch. Try again.');
      return;
    }

    setScreen('dashboard');
    await refreshContacts(sessionUser.userId);
    await refreshFriendRequests(sessionUser.userId);
    await refreshProfile(sessionUser.userId);
    setDashboardTab('chats');
    setStatus(`Unlocked: ${sessionUser.username}`);
    setPin('');
  };

  const handleSendFriendRequest = async () => {
    if (!sessionUser) {
      return;
    }

    if (contactUsername.trim().length < 3) {
      Alert.alert('Username required', 'Enter a valid contact username.');
      return;
    }

    try {
      const request = await sendFriendRequest(sessionUser.userId, contactUsername);
      setStatus(`Friend request sent to ${request.recipient_username}.`);
      setContactUsername('');
      await refreshFriendRequests(sessionUser.userId);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Could not add contact.';
      Alert.alert('Add contact failed', message);
      setStatus(message);
    }
  };

  const handleFriendRequestResponse = async (requestId: string, accept: boolean) => {
    if (!sessionUser) {
      return;
    }

    try {
      await respondToFriendRequest(sessionUser.userId, requestId, accept);
      await refreshFriendRequests(sessionUser.userId);
      if (accept) {
        await refreshContacts(sessionUser.userId);
      }
      setStatus(accept ? 'Friend request accepted.' : 'Friend request rejected.');
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Could not update friend request.';
      Alert.alert('Friend request', message);
      setStatus(message);
    }
  };

  const handleSaveProfile = async () => {
    if (!sessionUser) {
      return;
    }

    try {
      const profile = await updateUserProfile(sessionUser.userId, profileBio);
      setProfileBio(profile.profile_bio);
      setStatus('Profile saved on this device.');
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Could not save profile.';
      Alert.alert('Profile update failed', message);
    }
  };

  const handleSendMessage = async () => {
    if (!sessionUser || !activePeer) {
      Alert.alert('Select a contact', 'Add and select a contact first.');
      return;
    }

    if (!draftMessage.trim()) {
      Alert.alert('Message required', 'Type a message before sending.');
      return;
    }

    try {
      await sendEncryptedMessage(sessionUser.userId, activePeer, draftMessage);
      setDraftMessage('');
      setStatus(`Encrypted message sent to ${activePeer}.`);
      const synced = await syncAndDecryptMessages(sessionUser.userId, activePeer);
      setMessages(synced);
      await refreshConversationMeta(sessionUser.userId, activePeer);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Send failed.';
      Alert.alert('Send failed', message);
      setStatus(message);
    }
  };

  const handleSyncMessages = async () => {
    if (!sessionUser || !activePeer) {
      return;
    }

    try {
      const synced = await syncAndDecryptMessages(sessionUser.userId, activePeer);
      setMessages(synced);
      await refreshConversationMeta(sessionUser.userId, activePeer);
      setStatus(`Synced ${synced.length} encrypted messages.`);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Sync failed.';
      Alert.alert('Sync failed', message);
      setStatus(message);
    }
  };

  const handleLogout = async () => {
    setScreen('auth');
    setPin('');
    setPassword('');
    setUsername('');
    setSessionUser(null);
    if (sessionUser) {
      await setPresence(sessionUser.userId, 'offline');
    }
    await clearSession();
    setStatus('Logged out. Sign in again.');
  };

  if (!fontsLoaded) {
    return (
      <View style={styles.loadingScreen}>
        <Text style={styles.loadingText}>Loading Homy...</Text>
      </View>
    );
  }

  if (screen === 'dashboard' && sessionUser) {
    return (
      <View style={styles.screen}>
        <BlurView intensity={isBackgrounded ? 100 : 0} tint="dark" style={StyleSheet.absoluteFill} />
        {isBackgrounded ? <View pointerEvents="none" style={styles.privacyScrim} /> : null}
        <StatusBar style="light" />
        <SafeAreaView style={styles.safeArea}>
          <View style={styles.dashboardShell}>
            <ScrollView contentContainerStyle={styles.dashboardScrollContent}>
              <Text style={styles.dashboardTitle}>Homy</Text>
            <View style={[styles.dashboardCard, dashboardTab === 'settings' && styles.hidden]}>
              <Text style={styles.dashboardLabel}>Welcome back</Text>
              <Text style={styles.dashboardUser}>{sessionUser.username}</Text>
              <Text style={styles.dashboardStatus}>{status}</Text>

              <View style={styles.sectionSpacer}>
                <Text style={styles.label}>Add Friend</Text>
                <TextInput
                  value={contactUsername}
                  onChangeText={setContactUsername}
                  placeholder="Exact username"
                  placeholderTextColor="#7D7D87"
                  autoCapitalize="none"
                  autoCorrect={false}
                  style={styles.input}
                />
                <Pressable style={styles.secondaryButton} onPress={handleSendFriendRequest}>
                  <Text style={styles.secondaryButtonText}>Send friend request</Text>
                </Pressable>
              </View>

              <View style={styles.sectionSpacer}>
                <Text style={styles.label}>Friend requests</Text>
                {incomingRequests.length === 0 ? (
                  <Text style={styles.metaText}>No pending requests.</Text>
                ) : (
                  incomingRequests.map((request) => (
                    <View key={request.id} style={styles.requestRow}>
                      <Text style={styles.contactChipText}>{request.requester_username}</Text>
                      <View style={styles.requestActions}>
                        <Pressable
                          style={styles.requestButton}
                          onPress={() => void handleFriendRequestResponse(request.id, true)}
                        >
                          <Text style={styles.requestButtonText}>Accept</Text>
                        </Pressable>
                        <Pressable
                          style={styles.requestButtonMuted}
                          onPress={() => void handleFriendRequestResponse(request.id, false)}
                        >
                          <Text style={styles.requestButtonText}>Reject</Text>
                        </Pressable>
                      </View>
                    </View>
                  ))
                )}
              </View>

              <View style={styles.sectionSpacer}>
                <Text style={styles.label}>Contacts</Text>
                {contacts.length === 0 ? (
                  <Text style={styles.metaText}>No contacts yet.</Text>
                ) : (
                  contacts.map((contact) => (
                    <Pressable
                      key={contact.id}
                      style={[
                        styles.contactChip,
                        activePeer === contact.username && styles.contactChipActive,
                      ]}
                      onPress={async () => {
                        setActivePeer(contact.username);
                        if (sessionUser) {
                          await refreshConversationMeta(sessionUser.userId, contact.username);
                        }
                      }}
                    >
                      <Text style={styles.contactChipText}>
                        {contact.contact_user_id === sessionUser.userId ? 'You (self-chat)' : contact.username}
                      </Text>
                    </Pressable>
                  ))
                )}
              </View>

              <View style={styles.sectionSpacer}>
                <Text style={styles.label}>Chat</Text>
                <TextInput
                  value={draftMessage}
                  onChangeText={(value) => {
                    setDraftMessage(value);
                    if (typingTimer.current) {
                      clearTimeout(typingTimer.current);
                    }
                    if (sessionUser && activePeer) {
                      typingTimer.current = setTimeout(() => {
                        void setTypingState(sessionUser.userId, activePeer, value.trim().length > 0);
                      }, 250);
                    }
                  }}
                  placeholder={activePeer === sessionUser.username ? 'Message yourself (text only)' : activePeer ? `Message ${activePeer}` : 'Add a friend to start chatting'}
                  placeholderTextColor="#7D7D87"
                  autoCapitalize="sentences"
                  style={styles.input}
                />
                <View style={styles.buttonRow}>
                  <Pressable style={styles.secondaryButton} onPress={handleSendMessage}>
                    <Text style={styles.secondaryButtonText}>Send encrypted</Text>
                  </Pressable>
                  <Pressable style={styles.secondaryButton} onPress={handleSyncMessages}>
                    <Text style={styles.secondaryButtonText}>Sync</Text>
                  </Pressable>
                </View>

                {activePeer ? (
                  <Text style={styles.metaText}>
                    {isPeerTyping ? `${activePeer} is typing...` : `${activePeer} is ${peerPresence}`}
                    {peerReadCount > 0 ? ` • read ${peerReadCount}` : ''}
                  </Text>
                ) : null}

                {messages.slice(-6).map((item) => (
                  <View key={item.id} style={styles.messageRow}>
                    <Text style={styles.messageMeta}>{item.senderId === sessionUser.userId ? 'You' : activePeer}</Text>
                    <Text style={styles.messageText}>{item.text}</Text>
                  </View>
                ))}
              </View>
            </View>

            {dashboardTab === 'settings' ? (
              <View style={styles.dashboardCard}>
                <Text style={styles.dashboardLabel}>Account</Text>
                <Text style={styles.dashboardUser}>{sessionUser.username}</Text>
                <Text style={styles.dashboardStatus}>Your local database and identity keys stay on this device.</Text>
                <Text style={styles.label}>Profile bio</Text>
                <TextInput
                  value={profileBio}
                  onChangeText={setProfileBio}
                  placeholder="Add a short profile bio"
                  placeholderTextColor="#7D7D87"
                  maxLength={160}
                  multiline
                  style={[styles.input, styles.profileInput]}
                />
                <Pressable style={styles.secondaryButton} onPress={handleSaveProfile}>
                  <Text style={styles.secondaryButtonText}>Save profile</Text>
                </Pressable>
                <View style={styles.metaBox}>
                  <Text style={styles.metaTitle}>Privacy status</Text>
                  <Text style={styles.metaText}>Messages are encrypted before they leave Homy. Link previews are disabled.</Text>
                </View>
                <Text style={styles.status}>{status}</Text>
              </View>
            ) : null}

            <Pressable style={styles.primaryButton} onPress={handleLogout}>
              <Text style={styles.primaryButtonText}>Lock & sign out</Text>
            </Pressable>
            <View style={styles.bottomTabs}>
              <Pressable
                accessibilityRole="tab"
                accessibilityState={{ selected: dashboardTab === 'chats' }}
                style={[styles.tabButton, dashboardTab === 'chats' && styles.tabButtonActive]}
                onPress={() => setDashboardTab('chats')}
              >
                <Text style={styles.tabIcon}>◌</Text>
                <Text style={styles.tabText}>Chats</Text>
              </Pressable>
              <Pressable
                accessibilityRole="tab"
                accessibilityState={{ selected: dashboardTab === 'settings' }}
                style={[styles.tabButton, dashboardTab === 'settings' && styles.tabButtonActive]}
                onPress={() => setDashboardTab('settings')}
              >
                <Text style={styles.tabIcon}>⚙</Text>
                <Text style={styles.tabText}>Settings</Text>
              </Pressable>
            </View>
            </ScrollView>
          </View>
        </SafeAreaView>
      </View>
    );
  }

  if (screen === 'pin' && sessionUser) {
    return (
      <View style={styles.screen}>
        <BlurView intensity={isBackgrounded ? 100 : 0} tint="dark" style={StyleSheet.absoluteFill} />
        {isBackgrounded ? <View pointerEvents="none" style={styles.privacyScrim} /> : null}
        <StatusBar style="light" />
        <SafeAreaView style={styles.safeArea}>
          <View style={styles.shell}>
            <Text style={styles.title}>Unlock Homy</Text>
            <Text style={styles.subtitle}>Welcome back, {sessionUser.username}</Text>

            <View style={styles.card}>
              <Text style={styles.label}>PIN</Text>
              <TextInput
                value={pin}
                onChangeText={setPin}
                placeholder="Enter 4-digit PIN"
                placeholderTextColor="#7D7D87"
                keyboardType="number-pad"
                secureTextEntry
                maxLength={6}
                style={styles.input}
              />

              <Pressable style={styles.primaryButton} onPress={handleUnlock}>
                <Text style={styles.primaryButtonText}>Unlock</Text>
              </Pressable>

              <Text style={styles.status}>{status}</Text>
            </View>
          </View>
        </SafeAreaView>
      </View>
    );
  }

  return (
    <View style={styles.screen}>
      <BlurView intensity={isBackgrounded ? 100 : 0} tint="dark" style={StyleSheet.absoluteFill} />
      {isBackgrounded ? <View pointerEvents="none" style={styles.privacyScrim} /> : null}
      <StatusBar style="light" />

      <SafeAreaView style={styles.safeArea}>
        <View style={styles.shell}>
          <View style={styles.headerRow}>
            <Text style={styles.title}>Homy</Text>
            <Text style={styles.subtitle}>Private E2EE</Text>
          </View>

          <View style={styles.modeRow}>
            <Pressable
              style={[styles.modeButton, mode === 'signup' && styles.modeButtonActive]}
              onPress={() => setMode('signup')}
            >
              <Text style={[styles.modeText, mode === 'signup' && styles.modeTextActive]}>Create</Text>
            </Pressable>
            <Pressable
              style={[styles.modeButton, mode === 'login' && styles.modeButtonActive]}
              onPress={() => setMode('login')}
            >
              <Text style={[styles.modeText, mode === 'login' && styles.modeTextActive]}>Login</Text>
            </Pressable>
          </View>

          <View style={styles.card}>
            <Text style={styles.label}>Username</Text>
            <TextInput
              value={username}
              onChangeText={setUsername}
              placeholder="3-20 chars"
              placeholderTextColor="#7D7D87"
              autoCapitalize="none"
              autoCorrect={false}
              style={styles.input}
            />

            <Text style={styles.label}>Password</Text>
            <TextInput
              value={password}
              onChangeText={setPassword}
              placeholder="Choose a password"
              placeholderTextColor="#7D7D87"
              secureTextEntry
              style={styles.input}
            />

            <Text style={styles.label}>App PIN</Text>
            <TextInput
              value={pin}
              onChangeText={setPin}
              placeholder="4 digits"
              placeholderTextColor="#7D7D87"
              keyboardType="number-pad"
              secureTextEntry
              maxLength={6}
              style={styles.input}
            />

            <View style={styles.metaBox}>
              <Text style={styles.metaTitle}>Recovery phrase</Text>
              <Text style={styles.metaText}>A 12-word BIP-39 phrase is shown once after account creation.</Text>
            </View>

            <Pressable
              style={[styles.primaryButton, (!canSubmit || isSubmitting) && styles.primaryButtonDisabled]}
              onPress={handleSubmit}
              disabled={!canSubmit || isSubmitting}
            >
              <Text style={styles.primaryButtonText}>
                {isSubmitting ? 'Preparing...' : mode === 'signup' ? 'Create account' : 'Unlock'}
              </Text>
            </Pressable>

            <Text style={styles.status}>{isBooting ? 'Starting up...' : status}</Text>
          </View>
        </View>
      </SafeAreaView>
    </View>
  );
}

const styles = StyleSheet.create({
  screen: {
    flex: 1,
    backgroundColor: '#121212',
  },
  safeArea: {
    flex: 1,
  },
  loadingScreen: {
    flex: 1,
    backgroundColor: '#121212',
    alignItems: 'center',
    justifyContent: 'center',
  },
  loadingText: {
    color: '#FFFFFF',
    fontSize: 18,
    fontFamily: 'Inter_600SemiBold',
  },
  privacyScrim: {
    position: 'absolute',
    top: 0,
    right: 0,
    bottom: 0,
    left: 0,
    backgroundColor: '#121212',
    opacity: 0.96,
  },
  shell: {
    flex: 1,
    paddingHorizontal: 22,
    paddingTop: 32,
    paddingBottom: 24,
    justifyContent: 'center',
  },
  headerRow: {
    marginBottom: 20,
  },
  title: {
    color: '#FFFFFF',
    fontSize: 32,
    letterSpacing: -0.8,
    fontFamily: 'Inter_700Bold',
  },
  subtitle: {
    color: '#A0A0B0',
    fontSize: 14,
    marginTop: 8,
    fontFamily: 'Inter_500Medium',
  },
  modeRow: {
    flexDirection: 'row',
    backgroundColor: '#1E1E1E',
    borderRadius: 14,
    padding: 4,
    marginBottom: 18,
  },
  modeButton: {
    flex: 1,
    borderRadius: 10,
    paddingVertical: 10,
    alignItems: 'center',
  },
  modeButtonActive: {
    backgroundColor: '#5E5CE6',
  },
  modeText: {
    color: '#A0A0B0',
    fontSize: 14,
    fontFamily: 'Inter_600SemiBold',
  },
  modeTextActive: {
    color: '#FFFFFF',
  },
  card: {
    backgroundColor: 'rgba(30, 30, 30, 0.94)',
    borderRadius: 24,
    padding: 18,
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.05)',
    shadowColor: '#000000',
    shadowOffset: { width: 0, height: 8 },
    shadowOpacity: 0.22,
    shadowRadius: 18,
    elevation: 10,
  },
  dashboardShell: {
    flex: 1,
    paddingHorizontal: 22,
    paddingTop: 32,
    paddingBottom: 24,
    justifyContent: 'center',
  },
  dashboardScrollContent: {
    paddingBottom: 24,
  },
  hidden: {
    display: 'none',
  },
  dashboardTitle: {
    color: '#FFFFFF',
    fontSize: 32,
    letterSpacing: -0.8,
    fontFamily: 'Inter_700Bold',
    marginBottom: 16,
  },
  dashboardCard: {
    backgroundColor: 'rgba(30, 30, 30, 0.94)',
    borderRadius: 24,
    padding: 20,
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.05)',
    marginBottom: 20,
  },
  dashboardLabel: {
    color: '#A0A0B0',
    fontSize: 12,
    fontFamily: 'Inter_500Medium',
    marginBottom: 8,
  },
  dashboardUser: {
    color: '#FFFFFF',
    fontSize: 28,
    fontFamily: 'Inter_700Bold',
  },
  dashboardStatus: {
    color: '#A0A0B0',
    fontSize: 14,
    fontFamily: 'Inter_400Regular',
    marginTop: 12,
    lineHeight: 22,
  },
  sectionSpacer: {
    marginTop: 16,
  },
  secondaryButton: {
    borderRadius: 12,
    borderWidth: 1,
    borderColor: 'rgba(94, 92, 230, 0.6)',
    paddingVertical: 10,
    alignItems: 'center',
    marginTop: 10,
    backgroundColor: 'rgba(94, 92, 230, 0.14)',
  },
  secondaryButtonText: {
    color: '#FFFFFF',
    fontSize: 14,
    fontFamily: 'Inter_600SemiBold',
  },
  contactChip: {
    marginTop: 8,
    borderRadius: 10,
    paddingHorizontal: 12,
    paddingVertical: 8,
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.12)',
    backgroundColor: 'rgba(255,255,255,0.02)',
  },
  contactChipActive: {
    borderColor: '#5E5CE6',
    backgroundColor: 'rgba(94, 92, 230, 0.2)',
  },
  contactChipText: {
    color: '#FFFFFF',
    fontSize: 13,
    fontFamily: 'Inter_500Medium',
  },
  requestRow: {
    marginTop: 8,
    padding: 10,
    borderRadius: 10,
    backgroundColor: 'rgba(255,255,255,0.03)',
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.08)',
  },
  requestActions: {
    flexDirection: 'row',
    gap: 8,
    marginTop: 8,
  },
  requestButton: {
    flex: 1,
    borderRadius: 8,
    paddingVertical: 8,
    alignItems: 'center',
    backgroundColor: '#5E5CE6',
  },
  requestButtonMuted: {
    flex: 1,
    borderRadius: 8,
    paddingVertical: 8,
    alignItems: 'center',
    backgroundColor: 'rgba(255,255,255,0.10)',
  },
  requestButtonText: {
    color: '#FFFFFF',
    fontSize: 12,
    fontFamily: 'Inter_600SemiBold',
  },
  buttonRow: {
    flexDirection: 'row',
    gap: 10,
    marginTop: 4,
  },
  bottomTabs: {
    flexDirection: 'row',
    backgroundColor: '#1E1E1E',
    borderRadius: 16,
    padding: 4,
    marginTop: 16,
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.06)',
  },
  tabButton: {
    flex: 1,
    alignItems: 'center',
    borderRadius: 12,
    paddingVertical: 9,
  },
  tabButtonActive: {
    backgroundColor: 'rgba(94, 92, 230, 0.24)',
  },
  tabIcon: {
    color: '#A0A0B0',
    fontSize: 17,
    lineHeight: 18,
  },
  tabText: {
    color: '#A0A0B0',
    fontSize: 11,
    marginTop: 3,
    fontFamily: 'Inter_600SemiBold',
  },
  messageRow: {
    marginTop: 10,
    padding: 10,
    borderRadius: 10,
    backgroundColor: 'rgba(255,255,255,0.03)',
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.06)',
  },
  messageMeta: {
    color: '#A0A0B0',
    fontSize: 11,
    fontFamily: 'Inter_500Medium',
    marginBottom: 4,
  },
  messageText: {
    color: '#FFFFFF',
    fontSize: 14,
    fontFamily: 'Inter_400Regular',
    lineHeight: 20,
  },
  label: {
    color: '#FFFFFF',
    fontSize: 14,
    marginBottom: 8,
    marginTop: 6,
    fontFamily: 'Inter_600SemiBold',
  },
  input: {
    backgroundColor: '#1A1A1C',
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.05)',
    borderRadius: 12,
    color: '#FFFFFF',
    paddingHorizontal: 14,
    paddingVertical: 12,
    fontSize: 15,
    marginBottom: 12,
    fontFamily: 'Inter_400Regular',
  },
  profileInput: {
    minHeight: 84,
    textAlignVertical: 'top',
  },
  metaBox: {
    backgroundColor: '#17171A',
    borderRadius: 12,
    padding: 12,
    marginTop: 4,
    marginBottom: 16,
  },
  metaTitle: {
    color: '#FFFFFF',
    fontSize: 12,
    marginBottom: 4,
    fontFamily: 'Inter_600SemiBold',
  },
  metaText: {
    color: '#A0A0B0',
    fontSize: 12,
    lineHeight: 18,
    fontFamily: 'Inter_400Regular',
  },
  primaryButton: {
    backgroundColor: '#5E5CE6',
    borderRadius: 12,
    paddingVertical: 14,
    alignItems: 'center',
    justifyContent: 'center',
  },
  primaryButtonDisabled: {
    opacity: 0.45,
  },
  primaryButtonText: {
    color: '#FFFFFF',
    fontSize: 15,
    fontFamily: 'Inter_600SemiBold',
  },
  status: {
    color: '#A0A0B0',
    fontSize: 12,
    marginTop: 14,
    lineHeight: 18,
    fontFamily: 'Inter_500Medium',
  },
});
