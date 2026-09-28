import { BlurView } from 'expo-blur';
import { useFonts } from 'expo-font';
import {
  Inter_400Regular,
  Inter_500Medium,
  Inter_600SemiBold,
  Inter_700Bold,
} from '@expo-google-fonts/inter';
import { useEffect, useRef, useState } from 'react';
import {
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
  loginAccount,
  registerAccount,
  restoreSession,
  setPin,
  signOut,
  startPresenceHeartbeat,
  supabase,
  validateUsername,
  verifyPin,
} from './lib/homyCore';

type FlowState = 'boot' | 'auth' | 'pinSetup' | 'pinUnlock' | 'dashboard';
type AuthMode = 'register' | 'login';

type SessionUser = {
  userId: string;
  username: string;
};

export default function App() {
  const [flow, setFlow] = useState<FlowState>('boot');
  const [authMode, setAuthMode] = useState<AuthMode>('register');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [pin, setPinValue] = useState('');
  const [confirmPin, setConfirmPin] = useState('');
  const [sessionUser, setSessionUser] = useState<SessionUser | null>(null);
  const [needsPinSetup, setNeedsPinSetup] = useState(false);
  const [recoveryPhrase, setRecoveryPhrase] = useState('');
  const [hasSavedRecoveryPhrase, setHasSavedRecoveryPhrase] = useState(false);
  const [showRecoveryPhrase, setShowRecoveryPhrase] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isBackgrounded, setIsBackgrounded] = useState(false);
  const heartbeatStop = useRef<(() => void) | null>(null);

  const [fontsLoaded] = useFonts({
    Inter_400Regular,
    Inter_500Medium,
    Inter_600SemiBold,
    Inter_700Bold,
  });

  useEffect(() => {
    let mounted = true;

    const boot = async () => {
      const restored = await restoreSession();
      if (!mounted) {
        return;
      }

      if (!restored) {
        setFlow('auth');
        return;
      }

      setSessionUser({ userId: restored.userId, username: restored.username });
      setNeedsPinSetup(restored.needsPinSetup);
      setFlow(restored.needsPinSetup ? 'pinSetup' : 'pinUnlock');
    };

    void boot();
    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    if (!supabase) {
      return;
    }

    const { data } = supabase.auth.onAuthStateChange((event) => {
      if (event === 'SIGNED_OUT') {
        heartbeatStop.current?.();
        heartbeatStop.current = null;
        setSessionUser(null);
        setNeedsPinSetup(false);
        setFlow('auth');
      }
    });

    return () => data.subscription.unsubscribe();
  }, []);

  useEffect(() => {
    const subscription = AppState.addEventListener('change', (nextState) => {
      const backgrounded = nextState === 'background' || nextState === 'inactive';
      setIsBackgrounded(backgrounded);

      if (backgrounded && sessionUser) {
        setPinValue('');
        setConfirmPin('');
        setErrorMessage('');
        setFlow(needsPinSetup ? 'pinSetup' : 'pinUnlock');
      }
    });

    return () => subscription.remove();
  }, [needsPinSetup, sessionUser]);

  useEffect(() => {
    if (flow !== 'dashboard' || !sessionUser) {
      return;
    }

    heartbeatStop.current?.();
    heartbeatStop.current = startPresenceHeartbeat(sessionUser.userId);

    return () => {
      heartbeatStop.current?.();
      heartbeatStop.current = null;
    };
  }, [flow, sessionUser]);

  const clearAuthError = () => {
    if (errorMessage) {
      setErrorMessage('');
    }
  };

  const handleRegister = async () => {
    const usernameError = validateUsername(username);
    if (usernameError) {
      setErrorMessage(usernameError);
      return;
    }
    if (password.length < 6) {
      setErrorMessage('Password must be at least 6 characters.');
      return;
    }
    if (!/^\d{4,8}$/.test(pin)) {
      setErrorMessage('PIN must contain 4 to 8 digits.');
      return;
    }
    if (pin !== confirmPin) {
      setErrorMessage('PIN entries do not match.');
      return;
    }

    setIsSubmitting(true);
    setErrorMessage('');
    try {
      const result = await registerAccount(username, password, pin);
      setSessionUser({ userId: result.userId, username: result.username });
      setNeedsPinSetup(false);
      setRecoveryPhrase(result.mnemonic);
      setHasSavedRecoveryPhrase(false);
      setShowRecoveryPhrase(true);
      setPassword('');
      setPinValue('');
      setConfirmPin('');
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Could not create the account.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleLogin = async () => {
    const usernameError = validateUsername(username);
    if (usernameError) {
      setErrorMessage(usernameError);
      return;
    }
    if (!password) {
      setErrorMessage('Enter your password.');
      return;
    }

    setIsSubmitting(true);
    setErrorMessage('');
    try {
      const result = await loginAccount(username, password);
      setSessionUser({ userId: result.userId, username: result.username });
      setNeedsPinSetup(result.needsPinSetup);
      setPassword('');
      setFlow(result.needsPinSetup ? 'pinSetup' : 'pinUnlock');
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Could not sign in.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handlePinSetup = async () => {
    if (!sessionUser) {
      setFlow('auth');
      return;
    }
    if (!/^\d{4,8}$/.test(pin)) {
      setErrorMessage('PIN must contain 4 to 8 digits.');
      return;
    }
    if (pin !== confirmPin) {
      setErrorMessage('PIN entries do not match.');
      return;
    }

    setIsSubmitting(true);
    setErrorMessage('');
    try {
      await setPin(sessionUser.userId, pin);
      setNeedsPinSetup(false);
      setPinValue('');
      setConfirmPin('');
      setFlow('dashboard');
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Could not save your PIN.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handlePinUnlock = async () => {
    if (!sessionUser) {
      setFlow('auth');
      return;
    }
    if (!/^\d{4,8}$/.test(pin)) {
      setErrorMessage('Enter your 4 to 8 digit PIN.');
      return;
    }

    setIsSubmitting(true);
    setErrorMessage('');
    try {
      const valid = await verifyPin(sessionUser.userId, pin);
      if (!valid) {
        setErrorMessage('That PIN is incorrect.');
        return;
      }
      setPinValue('');
      setFlow('dashboard');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleLogout = async () => {
    if (!sessionUser) {
      setFlow('auth');
      return;
    }

    heartbeatStop.current?.();
    heartbeatStop.current = null;
    await signOut(sessionUser.userId);
    setSessionUser(null);
    setNeedsPinSetup(false);
    setPinValue('');
    setConfirmPin('');
    setUsername('');
    setPassword('');
    setErrorMessage('');
    setShowRecoveryPhrase(false);
    setRecoveryPhrase('');
    setFlow('auth');
  };

  if (!fontsLoaded || flow === 'boot') {
    return (
      <View style={styles.loadingScreen}>
        <Text style={styles.loadingText}>Loading Homy...</Text>
      </View>
    );
  }

  const renderAuth = () => {
    if (showRecoveryPhrase) {
      const words = recoveryPhrase.split(' ');
      return (
        <View style={styles.card}>
          <Text style={styles.title}>Save your recovery phrase</Text>
          <Text style={styles.subtitle}>
            This is the only way to restore your history on a new device. Homy cannot recover it for you.
          </Text>
          <View style={styles.phraseGrid}>
            {words.map((word, index) => (
              <View key={`${word}-${index}`} style={styles.phraseCell}>
                <Text style={styles.phraseNumber}>{index + 1}</Text>
                <Text style={styles.phraseWord}>{word}</Text>
              </View>
            ))}
          </View>
          <Pressable
            accessibilityRole="checkbox"
            accessibilityState={{ checked: hasSavedRecoveryPhrase }}
            style={styles.checkboxRow}
            onPress={() => setHasSavedRecoveryPhrase((saved) => !saved)}
          >
            <View style={[styles.checkbox, hasSavedRecoveryPhrase && styles.checkboxChecked]}>
              {hasSavedRecoveryPhrase ? <Text style={styles.checkboxMark}>✓</Text> : null}
            </View>
            <Text style={styles.checkboxText}>I have saved my recovery phrase</Text>
          </Pressable>
          <Pressable
            style={[styles.primaryButton, !hasSavedRecoveryPhrase && styles.primaryButtonDisabled]}
            onPress={() => setFlow('dashboard')}
            disabled={!hasSavedRecoveryPhrase}
          >
            <Text style={styles.primaryButtonText}>Continue</Text>
          </Pressable>
        </View>
      );
    }

    const usernameError = username.length > 0 ? validateUsername(username) : null;
    return (
      <View style={styles.card}>
        <View style={styles.modeRow}>
          <Pressable
            style={[styles.modeButton, authMode === 'register' && styles.modeButtonActive]}
            onPress={() => {
              setAuthMode('register');
              setErrorMessage('');
            }}
          >
            <Text style={[styles.modeText, authMode === 'register' && styles.modeTextActive]}>Register</Text>
          </Pressable>
          <Pressable
            style={[styles.modeButton, authMode === 'login' && styles.modeButtonActive]}
            onPress={() => {
              setAuthMode('login');
              setErrorMessage('');
            }}
          >
            <Text style={[styles.modeText, authMode === 'login' && styles.modeTextActive]}>Login</Text>
          </Pressable>
        </View>

        <Text style={styles.label}>Username</Text>
        <TextInput
          value={username}
          onChangeText={(value) => {
            setUsername(value);
            clearAuthError();
          }}
          placeholder="lowercase_username"
          placeholderTextColor="#7D7D87"
          autoCapitalize="none"
          autoCorrect={false}
          style={styles.input}
        />
        {usernameError ? <Text style={styles.fieldError}>{usernameError}</Text> : null}

        <Text style={styles.label}>Password</Text>
        <TextInput
          value={password}
          onChangeText={(value) => {
            setPassword(value);
            clearAuthError();
          }}
          placeholder={authMode === 'register' ? 'At least 6 characters' : 'Your password'}
          placeholderTextColor="#7D7D87"
          secureTextEntry
          style={styles.input}
        />

        {authMode === 'register' ? (
          <>
            <Text style={styles.label}>PIN</Text>
            <TextInput
              value={pin}
              onChangeText={(value) => {
                setPinValue(value.replace(/[^0-9]/g, '').slice(0, 8));
                clearAuthError();
              }}
              placeholder="4 to 8 digits"
              placeholderTextColor="#7D7D87"
              keyboardType="number-pad"
              secureTextEntry
              style={styles.input}
            />
            <Text style={styles.label}>Confirm PIN</Text>
            <TextInput
              value={confirmPin}
              onChangeText={(value) => {
                setConfirmPin(value.replace(/[^0-9]/g, '').slice(0, 8));
                clearAuthError();
              }}
              placeholder="Repeat your PIN"
              placeholderTextColor="#7D7D87"
              keyboardType="number-pad"
              secureTextEntry
              style={styles.input}
            />
          </>
        ) : null}

        {errorMessage ? <Text style={styles.inlineError}>{errorMessage}</Text> : null}
        <Pressable
          style={[styles.primaryButton, isSubmitting && styles.primaryButtonDisabled]}
          onPress={() => void (authMode === 'register' ? handleRegister() : handleLogin())}
          disabled={isSubmitting}
        >
          <Text style={styles.primaryButtonText}>
            {isSubmitting ? 'Please wait...' : authMode === 'register' ? 'Create account' : 'Sign in'}
          </Text>
        </Pressable>
      </View>
    );
  };

  const renderPinSetup = () => (
    <View style={styles.card}>
      <Text style={styles.title}>Set your app PIN</Text>
      <Text style={styles.subtitle}>This PIN unlocks Homy on this device.</Text>
      <Text style={styles.label}>PIN</Text>
      <TextInput
        value={pin}
        onChangeText={(value) => setPinValue(value.replace(/[^0-9]/g, '').slice(0, 8))}
        placeholder="4 to 8 digits"
        placeholderTextColor="#7D7D87"
        keyboardType="number-pad"
        secureTextEntry
        style={styles.input}
      />
      <Text style={styles.label}>Confirm PIN</Text>
      <TextInput
        value={confirmPin}
        onChangeText={(value) => setConfirmPin(value.replace(/[^0-9]/g, '').slice(0, 8))}
        placeholder="Repeat your PIN"
        placeholderTextColor="#7D7D87"
        keyboardType="number-pad"
        secureTextEntry
        style={styles.input}
      />
      {errorMessage ? <Text style={styles.inlineError}>{errorMessage}</Text> : null}
      <Pressable style={styles.primaryButton} onPress={() => void handlePinSetup} disabled={isSubmitting}>
        <Text style={styles.primaryButtonText}>{isSubmitting ? 'Saving...' : 'Save PIN'}</Text>
      </Pressable>
    </View>
  );

  const renderPinUnlock = () => (
    <View style={styles.card}>
      <Text style={styles.title}>Unlock Homy</Text>
      <Text style={styles.subtitle}>Welcome back, @{sessionUser?.username}</Text>
      <Text style={styles.label}>PIN</Text>
      <TextInput
        value={pin}
        onChangeText={(value) => setPinValue(value.replace(/[^0-9]/g, '').slice(0, 8))}
        placeholder="Enter your PIN"
        placeholderTextColor="#7D7D87"
        keyboardType="number-pad"
        secureTextEntry
        style={styles.input}
      />
      {errorMessage ? <Text style={styles.inlineError}>{errorMessage}</Text> : null}
      <Pressable style={styles.primaryButton} onPress={() => void handlePinUnlock} disabled={isSubmitting}>
        <Text style={styles.primaryButtonText}>{isSubmitting ? 'Checking...' : 'Unlock'}</Text>
      </Pressable>
    </View>
  );

  const renderDashboard = () => (
    <View style={styles.card}>
      <Text style={styles.title}>@{sessionUser?.username}</Text>
      <Text style={styles.signedIn}>Signed in</Text>
      <Text style={styles.subtitle}>Chats and friends return in the next milestone.</Text>
      <Pressable style={styles.primaryButton} onPress={() => void handleLogout}>
        <Text style={styles.primaryButtonText}>Log out</Text>
      </Pressable>
    </View>
  );

  return (
    <View style={styles.screen}>
      <StatusBar style="light" />
      <SafeAreaView style={styles.safeArea}>
        <ScrollView contentContainerStyle={styles.shell} keyboardShouldPersistTaps="handled">
          <Text style={styles.brand}>Homy</Text>
          <Text style={styles.headerSubtitle}>Private E2EE</Text>
          {flow === 'auth' ? renderAuth() : null}
          {flow === 'pinSetup' ? renderPinSetup() : null}
          {flow === 'pinUnlock' ? renderPinUnlock() : null}
          {flow === 'dashboard' ? renderDashboard() : null}
        </ScrollView>
      </SafeAreaView>
      {isBackgrounded ? (
        <View pointerEvents="none" style={styles.privacyOverlay}>
          <BlurView intensity={100} tint="dark" style={StyleSheet.absoluteFill} />
          <View style={styles.privacyScrim} />
        </View>
      ) : null}
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
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#121212',
  },
  loadingText: {
    color: '#FFFFFF',
    fontSize: 18,
    fontFamily: 'Inter_600SemiBold',
  },
  shell: {
    flexGrow: 1,
    width: '100%',
    maxWidth: 520,
    alignSelf: 'center',
    justifyContent: 'center',
    paddingHorizontal: 22,
    paddingVertical: 32,
  },
  brand: {
    color: '#FFFFFF',
    fontSize: 34,
    fontFamily: 'Inter_700Bold',
  },
  headerSubtitle: {
    color: '#A0A0B0',
    fontSize: 14,
    marginTop: 8,
    marginBottom: 20,
    fontFamily: 'Inter_500Medium',
  },
  card: {
    backgroundColor: 'rgba(30, 30, 30, 0.96)',
    borderRadius: 24,
    padding: 20,
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.06)',
    shadowColor: '#000000',
    shadowOffset: { width: 0, height: 8 },
    shadowOpacity: 0.22,
    shadowRadius: 18,
    elevation: 10,
  },
  title: {
    color: '#FFFFFF',
    fontSize: 26,
    lineHeight: 32,
    fontFamily: 'Inter_700Bold',
  },
  subtitle: {
    color: '#A0A0B0',
    fontSize: 14,
    lineHeight: 21,
    marginTop: 8,
    marginBottom: 18,
    fontFamily: 'Inter_400Regular',
  },
  modeRow: {
    flexDirection: 'row',
    backgroundColor: '#17171A',
    borderRadius: 14,
    padding: 4,
    marginBottom: 18,
  },
  modeButton: {
    flex: 1,
    alignItems: 'center',
    borderRadius: 10,
    paddingVertical: 10,
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
  label: {
    color: '#FFFFFF',
    fontSize: 14,
    marginTop: 6,
    marginBottom: 8,
    fontFamily: 'Inter_600SemiBold',
  },
  input: {
    backgroundColor: '#1A1A1C',
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.08)',
    borderRadius: 12,
    color: '#FFFFFF',
    paddingHorizontal: 14,
    paddingVertical: 12,
    fontSize: 15,
    marginBottom: 10,
    fontFamily: 'Inter_400Regular',
  },
  fieldError: {
    color: '#F3A4A4',
    fontSize: 12,
    lineHeight: 17,
    marginTop: -4,
    marginBottom: 5,
    fontFamily: 'Inter_400Regular',
  },
  inlineError: {
    color: '#F3A4A4',
    fontSize: 13,
    lineHeight: 19,
    marginTop: 6,
    marginBottom: 12,
    fontFamily: 'Inter_500Medium',
  },
  primaryButton: {
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#5E5CE6',
    borderRadius: 12,
    paddingVertical: 14,
    marginTop: 10,
  },
  primaryButtonDisabled: {
    opacity: 0.45,
  },
  primaryButtonText: {
    color: '#FFFFFF',
    fontSize: 15,
    fontFamily: 'Inter_600SemiBold',
  },
  phraseGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    marginTop: 2,
    marginBottom: 12,
  },
  phraseCell: {
    width: '33.3333%',
    minHeight: 54,
    padding: 6,
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.06)',
    backgroundColor: '#17171A',
  },
  phraseNumber: {
    color: '#7D7D87',
    fontSize: 10,
    fontFamily: 'Inter_500Medium',
  },
  phraseWord: {
    color: '#FFFFFF',
    fontSize: 13,
    marginTop: 4,
    fontFamily: 'Inter_600SemiBold',
  },
  checkboxRow: {
    flexDirection: 'row',
    alignItems: 'center',
    marginTop: 6,
    marginBottom: 6,
  },
  checkbox: {
    width: 22,
    height: 22,
    alignItems: 'center',
    justifyContent: 'center',
    borderWidth: 1,
    borderColor: '#7D7D87',
    borderRadius: 5,
    marginRight: 10,
  },
  checkboxChecked: {
    backgroundColor: '#5E5CE6',
    borderColor: '#5E5CE6',
  },
  checkboxMark: {
    color: '#FFFFFF',
    fontSize: 15,
    fontFamily: 'Inter_700Bold',
  },
  checkboxText: {
    flex: 1,
    color: '#FFFFFF',
    fontSize: 13,
    fontFamily: 'Inter_500Medium',
  },
  signedIn: {
    color: '#A0A0B0',
    fontSize: 14,
    marginTop: 12,
    fontFamily: 'Inter_600SemiBold',
  },
  privacyOverlay: {
    position: 'absolute',
    top: 0,
    right: 0,
    bottom: 0,
    left: 0,
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
});
