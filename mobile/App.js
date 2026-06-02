import React, { useState, useEffect } from 'react';
import {
    StyleSheet, Text, View, TextInput, TouchableOpacity,
    ActivityIndicator, Alert, StatusBar, SafeAreaView,
    Modal, ScrollView, Platform, AsyncStorage
} from 'react-native';
import { LinearGradient } from 'expo-linear-gradient';
import { MaterialCommunityIcons } from '@expo/vector-icons';
import { CameraView, useCameraPermissions } from 'expo-camera';
import * as DocumentPicker from 'expo-document-picker';
import Constants from 'expo-constants';
import AsyncStoragePkg from '@react-native-async-storage/async-storage';

const Storage = AsyncStoragePkg || AsyncStorage;

export default function App() {
    const [scanMode, setScanMode] = useState('url');
    const [inputValue, setInputValue] = useState('');
    const [selectedFile, setSelectedFile] = useState(null);
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState(null);
    const [permission, requestPermission] = useCameraPermissions();
    const [isScanning, setIsScanning] = useState(false);

    // AUTH
    const [token, setToken] = useState('');
    const [user, setUser] = useState(null);
    const [authModal, setAuthModal] = useState(false);
    const [authTab, setAuthTab] = useState('login'); // 'login' | 'register'
    const [historyModal, setHistoryModal] = useState(false);
    const [history, setHistory] = useState([]);

    // Login fields
    const [loginUser, setLoginUser] = useState('');
    const [loginPass, setLoginPass] = useState('');

    // Register fields
    const [regEmail, setRegEmail] = useState('');
    const [regOtp, setRegOtp] = useState('');
    const [regUser, setRegUser] = useState('');
    const [regPass, setRegPass] = useState('');
    const [regStep, setRegStep] = useState(1); // 1=email, 2=otp+info
    const [regLoading, setRegLoading] = useState(false);

    // API BASE
    const getApiBase = () => {
        if (Platform.OS === 'web') return 'http://localhost:8000/api';
        const debuggerHost = Constants.expoConfig?.hostUri;
        if (debuggerHost) {
            const ip = debuggerHost.split(':')[0];
            return `http://${ip}:8000/api`;
        }
        if (Platform.OS === 'android') return 'http://10.0.2.2:8000/api';
        return 'http://localhost:8000/api';
    };

    // Token yuklash
    useEffect(() => {
        loadToken();
    }, []);

    const loadToken = async () => {
        try {
            const saved = await Storage.getItem('fsr_token');
            if (saved) {
                setToken(saved);
                const API = getApiBase();
                const r = await fetch(`${API}/auth/me`, {
                    headers: { 'Authorization': `Bearer ${saved}` }
                });
                if (r.ok) {
                    const data = await r.json();
                    setUser(data);
                } else {
                    await Storage.removeItem('fsr_token');
                }
            }
        } catch (e) { console.log(e); }
    };

    const doLogin = async () => {
        if (!loginUser || !loginPass) {
            Alert.alert('Xatolik', 'Barcha maydonlarni to\'ldiring!');
            return;
        }
        const API = getApiBase();
        try {
            const r = await fetch(`${API}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: loginUser, password: loginPass })
            });
            const data = await r.json();
            if (!r.ok) { Alert.alert('Xatolik', data.detail || 'Noto\'g\'ri ma\'lumot'); return; }
            await Storage.setItem('fsr_token', data.token);
            setToken(data.token);
            setUser({ username: data.username, role: data.role });
            setAuthModal(false);
            setLoginUser(''); setLoginPass('');
            Alert.alert('✅ Xush kelibsiz!', `Salom, ${data.username}!`);
        } catch (e) {
            Alert.alert('Xatolik', 'Server bilan ulanib bo\'lmadi!');
        }
    };

    const sendOtp = async () => {
        if (!regEmail) { Alert.alert('Xatolik', 'Email kiriting!'); return; }
        setRegLoading(true);
        const API = getApiBase();
        try {
            const r = await fetch(`${API}/auth/send-otp`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: regEmail })
            });
            const data = await r.json();
            if (!r.ok) { Alert.alert('Xatolik', data.detail || 'Xatolik'); }
            else { setRegStep(2); Alert.alert('📧 Kod yuborildi!', 'Emailingizni tekshiring'); }
        } catch (e) {
            Alert.alert('Xatolik', 'Server bilan ulanib bo\'lmadi!');
        }
        setRegLoading(false);
    };

    const doRegister = async () => {
        if (!regOtp || !regUser || !regPass) {
            Alert.alert('Xatolik', 'Barcha maydonlarni to\'ldiring!');
            return;
        }
        if (regPass.length < 6) {
            Alert.alert('Xatolik', 'Parol kamida 6 ta belgi bo\'lishi kerak!');
            return;
        }
        setRegLoading(true);
        const API = getApiBase();
        try {
            const r = await fetch(`${API}/auth/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: regUser, email: regEmail, password: regPass, otp: regOtp })
            });
            const data = await r.json();
            if (!r.ok) { Alert.alert('Xatolik', data.detail || 'Xatolik'); }
            else {
                Alert.alert('✅ Muvaffaqiyatli!', 'Endi tizimga kiring');
                setAuthTab('login');
                setRegStep(1);
                setRegEmail(''); setRegOtp(''); setRegUser(''); setRegPass('');
            }
        } catch (e) {
            Alert.alert('Xatolik', 'Server bilan ulanib bo\'lmadi!');
        }
        setRegLoading(false);
    };

    const doLogout = async () => {
        await Storage.removeItem('fsr_token');
        setToken(''); setUser(null);
        Alert.alert('Chiqildi', 'Tizimdan chiqdingiz');
    };

    const loadHistory = async () => {
        if (!token) return;
        const API = getApiBase();
        try {
            const r = await fetch(`${API}/history`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const data = await r.json();
            setHistory(data);
        } catch (e) { console.log(e); }
    };

    const handleScan = async (scanInput = inputValue) => {
        // Login tekshiruv — SMS va Fayl uchun
        if ((scanMode === 'sms' || scanMode === 'file') && !user) {
            Alert.alert('🔐 Kirish kerak', 'SMS va fayl tekshirish uchun tizimga kiring', [
                { text: 'Bekor', style: 'cancel' },
                { text: 'Kirish', onPress: () => setAuthModal(true) }
            ]);
            return;
        }

        setLoading(true);
        setResult(null);
        const API = getApiBase();

        try {
            let endpoint = '/scan';
            let body = {};

            if (scanMode === 'url') {
                if (!scanInput) { Alert.alert('Xatolik', 'Havola kiriting!'); setLoading(false); return; }
                body = { url: scanInput };
            } else if (scanMode === 'sms') {
                if (!scanInput) { Alert.alert('Xatolik', 'SMS matnini kiriting!'); setLoading(false); return; }
                endpoint = '/scan/sms';
                body = { text: scanInput };
            } else if (scanMode === 'file') {
                if (!selectedFile) { Alert.alert('Xatolik', 'Fayl tanlang!'); setLoading(false); return; }
                endpoint = '/scan/file';
                body = { fileName: selectedFile.name, fileSize: selectedFile.size, fileType: selectedFile.mimeType };
            }

            const headers = {
                'Content-Type': 'application/json',
                'Bypass-Tunnel-Reminder': 'true'
            };
            if (token) headers['Authorization'] = `Bearer ${token}`;

            const response = await fetch(`${API}${endpoint}`, {
                method: 'POST', headers, body: JSON.stringify(body)
            });
            const data = await response.json();
            setResult(data.result);
        } catch (error) {
            Alert.alert('Xatolik', 'Server bilan bog\'lanishda xatolik.');
        } finally {
            setLoading(false);
        }
    };

    const pickDocument = async () => {
        if (!user) {
            Alert.alert('🔐 Kirish kerak', 'Fayl tekshirish uchun tizimga kiring', [
                { text: 'Bekor', style: 'cancel' },
                { text: 'Kirish', onPress: () => setAuthModal(true) }
            ]);
            return;
        }
        try {
            const res = await DocumentPicker.getDocumentAsync({});
            if (!res.canceled) { setSelectedFile(res.assets[0]); setResult(null); }
        } catch (err) { console.log(err); }
    };

    const startQrScan = async () => {
        if (!permission?.granted) {
            const { granted } = await requestPermission();
            if (!granted) { Alert.alert('Ruxsat kerak', 'Kamera ruxsati kerak'); return; }
        }
        setIsScanning(true);
    };

    const handleBarCodeScanned = ({ data }) => {
        setIsScanning(false);
        setScanMode('url');
        setInputValue(data);
        handleScan(data);
    };

    const renderInputSection = () => {
        if (scanMode === 'url') {
            return (
                <View style={styles.inputWrapper}>
                    <MaterialCommunityIcons name="link-variant" size={24} color="#94a3b8" style={styles.inputIcon} />
                    <TextInput
                        style={styles.input}
                        placeholder="https://example.com"
                        placeholderTextColor="#64748b"
                        value={inputValue}
                        onChangeText={setInputValue}
                        autoCapitalize="none"
                        keyboardType="url"
                    />
                    <TouchableOpacity onPress={startQrScan} style={styles.qrButton}>
                        <MaterialCommunityIcons name="qrcode-scan" size={24} color="#38bdf8" />
                    </TouchableOpacity>
                </View>
            );
        } else if (scanMode === 'sms') {
            if (!user) return (
                <View style={styles.lockBox}>
                    <MaterialCommunityIcons name="lock" size={36} color="#38bdf8" />
                    <Text style={styles.lockTitle}>SMS tekshirish uchun kiring</Text>
                    <Text style={styles.lockDesc}>SMS xabarlaridagi zararli havolalarni aniqlash uchun tizimga kiring</Text>
                    <TouchableOpacity style={styles.lockBtn} onPress={() => setAuthModal(true)}>
                        <Text style={styles.lockBtnText}>🔑 Tizimga kirish</Text>
                    </TouchableOpacity>
                </View>
            );
            return (
                <View style={[styles.inputWrapper, { height: 120, alignItems: 'flex-start', paddingTop: 15 }]}>
                    <MaterialCommunityIcons name="message-text-outline" size={24} color="#94a3b8" style={styles.inputIcon} />
                    <TextInput
                        style={[styles.input, { height: '100%', textAlignVertical: 'top' }]}
                        placeholder="SMS matnini bu yerga kiriting..."
                        placeholderTextColor="#64748b"
                        value={inputValue}
                        onChangeText={setInputValue}
                        multiline
                    />
                </View>
            );
        } else if (scanMode === 'file') {
            if (!user) return (
                <View style={styles.lockBox}>
                    <MaterialCommunityIcons name="lock" size={36} color="#38bdf8" />
                    <Text style={styles.lockTitle}>Fayl tekshirish uchun kiring</Text>
                    <Text style={styles.lockDesc}>Fayllarni xavfli kengaytmalar va virus belgilari uchun tekshirish uchun kiring</Text>
                    <TouchableOpacity style={styles.lockBtn} onPress={() => setAuthModal(true)}>
                        <Text style={styles.lockBtnText}>🔑 Tizimga kirish</Text>
                    </TouchableOpacity>
                </View>
            );
            return (
                <View style={styles.fileContainer}>
                    <TouchableOpacity style={styles.fileButton} onPress={pickDocument}>
                        <MaterialCommunityIcons name={selectedFile ? "file-check" : "file-upload"} size={40} color="#38bdf8" />
                        <Text style={styles.fileButtonText}>{selectedFile ? selectedFile.name : "Faylni tanlash"}</Text>
                        {selectedFile && <Text style={styles.fileSizeText}>{(selectedFile.size / 1024).toFixed(2)} KB</Text>}
                    </TouchableOpacity>
                </View>
            );
        }
    };

    return (
        <LinearGradient colors={['#0f172a', '#1e293b', '#0f172a']} style={styles.container}>
            <StatusBar barStyle="light-content" backgroundColor="#0f172a" />
            <SafeAreaView style={styles.safeArea}>
                <ScrollView contentContainerStyle={styles.scrollContent}>

                    {/* HEADER */}
                    <View style={styles.header}>
                        <MaterialCommunityIcons name="shield-check" size={64} color="#38bdf8" />
                        <Text style={styles.title}>FSR SafeScan</Text>
                        <Text style={styles.subtitle}>Professional Kiberxavfsizlik</Text>
                    </View>

                    {/* AUTH BAR */}
                    <View style={styles.authBar}>
                        {user ? (
                            <View style={styles.authUser}>
                                <View style={styles.authAvatar}>
                                    <Text style={styles.authAvatarText}>{user.username[0].toUpperCase()}</Text>
                                </View>
                                <View>
                                    <Text style={styles.authName}>{user.username}</Text>
                                    <Text style={styles.authRole}>{user.role === 'admin' ? '👑 Admin' : '🔐 Foydalanuvchi'}</Text>
                                </View>
                            </View>
                        ) : (
                            <View style={styles.authUser}>
                                <MaterialCommunityIcons name="account-circle" size={32} color="#64748b" />
                                <Text style={styles.guestText}>Mehmon</Text>
                            </View>
                        )}
                        <View style={styles.authBtns}>
                            {user ? (
                                <>
                                    <TouchableOpacity style={styles.historyBtn} onPress={() => { setHistoryModal(true); loadHistory(); }}>
                                        <Text style={styles.historyBtnText}>📋</Text>
                                    </TouchableOpacity>
                                    <TouchableOpacity style={styles.logoutBtn} onPress={doLogout}>
                                        <Text style={styles.logoutBtnText}>Chiqish</Text>
                                    </TouchableOpacity>
                                </>
                            ) : (
                                <TouchableOpacity style={styles.loginBtn} onPress={() => setAuthModal(true)}>
                                    <Text style={styles.loginBtnText}>Kirish</Text>
                                </TouchableOpacity>
                            )}
                        </View>
                    </View>

                    {/* MODE SWITCHER */}
                    <View style={styles.modeSwitcher}>
                        {['url', 'sms', 'file'].map(mode => (
                            <TouchableOpacity
                                key={mode}
                                style={[styles.modeButton, scanMode === mode && styles.modeButtonActive]}
                                onPress={() => { setScanMode(mode); setInputValue(''); setResult(null); setSelectedFile(null); }}
                            >
                                <Text style={[styles.modeText, scanMode === mode && styles.modeTextActive]}>
                                    {mode === 'url' ? '🔗 URL' : mode === 'sms' ? '💬 SMS' : '📁 FAYL'}
                                    {(mode === 'sms' || mode === 'file') && !user ? ' 🔒' : ''}
                                </Text>
                            </TouchableOpacity>
                        ))}
                    </View>

                    {/* CARD */}
                    <View style={styles.card}>
                        <Text style={styles.label}>
                            {scanMode === 'url' ? 'Havolani tekshirish' : scanMode === 'sms' ? 'SMS tekshirish' : 'Fayl tekshirish'}
                        </Text>
                        {renderInputSection()}
                        {(scanMode === 'url' || user) && (
                            <TouchableOpacity style={styles.button} onPress={() => handleScan()} disabled={loading}>
                                <LinearGradient colors={['#3b82f6', '#2563eb']} style={styles.buttonGradient} start={{ x: 0, y: 0 }} end={{ x: 1, y: 0 }}>
                                    {loading ? <ActivityIndicator color="#fff" /> : (
                                        <View style={styles.buttonContent}>
                                            <MaterialCommunityIcons name="radar" size={24} color="#fff" style={{ marginRight: 10 }} />
                                            <Text style={styles.buttonText}>SKANERLASH</Text>
                                        </View>
                                    )}
                                </LinearGradient>
                            </TouchableOpacity>
                        )}
                    </View>

                    {/* RESULT */}
                    {result && (
                        <View style={[styles.resultCard, result.safe ? styles.safeBorder : styles.dangerBorder]}>
                            {/* Preview */}
                            {result.preview && result.preview.title ? (
                                <View style={styles.previewBox}>
                                    <Text style={styles.previewSite}>
                                        {result.preview.content_type === 'video' ? '🎬' : result.preview.content_type === 'social' ? '📱' : '🌐'} {result.preview.site_name || result.preview.domain}
                                    </Text>
                                    <Text style={styles.previewTitle}>{result.preview.title}</Text>
                                    {result.preview.description ? (
                                        <Text style={styles.previewDesc}>{result.preview.description.substring(0, 120)}...</Text>
                                    ) : null}
                                </View>
                            ) : null}

                            <View style={styles.resultHeader}>
                                <MaterialCommunityIcons
                                    name={result.safe ? "shield-check-outline" : "alert-octagon-outline"}
                                    size={40} color={result.safe ? "#4ade80" : "#f87171"}
                                />
                                <Text style={[styles.resultTitle, { color: result.safe ? "#4ade80" : "#f87171" }]}>
                                    {result.safe ? 'XAVFSIZ' : 'XAVFLI'}
                                </Text>
                            </View>

                            <Text style={styles.scoreText}>Ishonch darajasi: {result.score}%</Text>

                            {/* VT Stats */}
                            {result.vtStats && (
                                <View style={styles.vtGrid}>
                                    <View style={styles.vtBox}><Text style={[styles.vtNum, { color: '#ef4444' }]}>{result.vtStats.malicious}</Text><Text style={styles.vtLbl}>Xavfli</Text></View>
                                    <View style={styles.vtBox}><Text style={[styles.vtNum, { color: '#f59e0b' }]}>{result.vtStats.suspicious}</Text><Text style={styles.vtLbl}>Shubhali</Text></View>
                                    <View style={styles.vtBox}><Text style={[styles.vtNum, { color: '#22c55e' }]}>{result.vtStats.harmless}</Text><Text style={styles.vtLbl}>Xavfsiz</Text></View>
                                    <View style={styles.vtBox}><Text style={[styles.vtNum, { color: '#64748b' }]}>{result.vtStats.undetected}</Text><Text style={styles.vtLbl}>Noma'lum</Text></View>
                                </View>
                            )}

                            {/* File Info */}
                            {result.fileInfo && (
                                <View style={styles.fileInfoBox}>
                                    <Text style={styles.fileInfoRow}><Text style={styles.fileInfoLabel}>Tur: </Text>{result.fileInfo.description}</Text>
                                    <Text style={styles.fileInfoRow}><Text style={styles.fileInfoLabel}>O'lcham: </Text>{result.fileInfo.size_kb} KB</Text>
                                </View>
                            )}

                            {/* Xulosa */}
                            <View style={[styles.conclusionBox, result.safe ? styles.conclusionSafe : styles.conclusionDanger]}>
                                <Text style={[styles.conclusionText, { color: result.safe ? '#86efac' : '#fca5a5' }]}>
                                    {result.safe
                                        ? '✅ Bu xavfsiz ko\'rinadi. Bemalol foydalanishingiz mumkin.'
                                        : '🚨 DIQQAT! Bu XAVFLI! Hech qanday ma\'lumot kiritmang!'}
                                </Text>
                            </View>

                            {/* Threats */}
                            {result.threats && result.threats.length > 0 && (
                                <View style={styles.threatsBox}>
                                    {result.threats.map((threat, i) => (
                                        <View key={i} style={styles.threatRow}>
                                            <MaterialCommunityIcons name="alert-circle-outline" size={16} color="#f87171" />
                                            <Text style={styles.threatText}>{threat}</Text>
                                        </View>
                                    ))}
                                </View>
                            )}
                        </View>
                    )}
                </ScrollView>

                {/* AUTH MODAL */}
                <Modal visible={authModal} animationType="slide" transparent onRequestClose={() => setAuthModal(false)}>
                    <View style={styles.modalOverlay}>
                        <View style={styles.modalBox}>
                            <Text style={styles.modalLogo}>🛡️</Text>
                            <Text style={styles.modalTitle}>FSR SafeScan</Text>

                            {/* TABS */}
                            <View style={styles.modalTabs}>
                                <TouchableOpacity style={[styles.modalTab, authTab === 'login' && styles.modalTabActive]} onPress={() => setAuthTab('login')}>
                                    <Text style={[styles.modalTabText, authTab === 'login' && styles.modalTabTextActive]}>Kirish</Text>
                                </TouchableOpacity>
                                <TouchableOpacity style={[styles.modalTab, authTab === 'register' && styles.modalTabActive]} onPress={() => { setAuthTab('register'); setRegStep(1); }}>
                                    <Text style={[styles.modalTabText, authTab === 'register' && styles.modalTabTextActive]}>Ro'yxat</Text>
                                </TouchableOpacity>
                            </View>

                            {/* LOGIN */}
                            {authTab === 'login' && (
                                <View>
                                    <TextInput style={styles.modalInput} placeholder="Foydalanuvchi nomi" placeholderTextColor="#64748b" value={loginUser} onChangeText={setLoginUser} autoCapitalize="none" />
                                    <TextInput style={styles.modalInput} placeholder="Parol" placeholderTextColor="#64748b" value={loginPass} onChangeText={setLoginPass} secureTextEntry />
                                    <TouchableOpacity style={styles.modalBtn} onPress={doLogin}>
                                        <Text style={styles.modalBtnText}>Kirish</Text>
                                    </TouchableOpacity>
                                </View>
                            )}

                            {/* REGISTER */}
                            {authTab === 'register' && regStep === 1 && (
                                <View>
                                    <TextInput style={styles.modalInput} placeholder="Email manzilingiz" placeholderTextColor="#64748b" value={regEmail} onChangeText={setRegEmail} keyboardType="email-address" autoCapitalize="none" />
                                    <TouchableOpacity style={styles.modalBtn} onPress={sendOtp} disabled={regLoading}>
                                        {regLoading ? <ActivityIndicator color="#fff" /> : <Text style={styles.modalBtnText}>📧 Kod yuborish</Text>}
                                    </TouchableOpacity>
                                </View>
                            )}

                            {authTab === 'register' && regStep === 2 && (
                                <View>
                                    <Text style={styles.otpInfo}>📧 {regEmail} ga kod yuborildi</Text>
                                    <TextInput style={[styles.modalInput, styles.otpInput]} placeholder="000000" placeholderTextColor="#64748b" value={regOtp} onChangeText={setRegOtp} keyboardType="number-pad" maxLength={6} />
                                    <TextInput style={styles.modalInput} placeholder="Foydalanuvchi nomi" placeholderTextColor="#64748b" value={regUser} onChangeText={setRegUser} autoCapitalize="none" />
                                    <TextInput style={styles.modalInput} placeholder="Parol (kamida 6 ta belgi)" placeholderTextColor="#64748b" value={regPass} onChangeText={setRegPass} secureTextEntry />
                                    <TouchableOpacity style={styles.modalBtn} onPress={doRegister} disabled={regLoading}>
                                        {regLoading ? <ActivityIndicator color="#fff" /> : <Text style={styles.modalBtnText}>✅ Ro'yxatdan o'tish</Text>}
                                    </TouchableOpacity>
                                    <TouchableOpacity onPress={sendOtp} style={{ marginTop: 10, alignItems: 'center' }}>
                                        <Text style={{ color: '#64748b', fontSize: 12 }}>Kodni qayta yuborish</Text>
                                    </TouchableOpacity>
                                </View>
                            )}

                            <TouchableOpacity onPress={() => setAuthModal(false)} style={styles.modalClose}>
                                <Text style={{ color: '#64748b', fontSize: 14 }}>Yopish</Text>
                            </TouchableOpacity>
                        </View>
                    </View>
                </Modal>

                {/* HISTORY MODAL */}
                <Modal visible={historyModal} animationType="slide" transparent onRequestClose={() => setHistoryModal(false)}>
                    <View style={styles.modalOverlay}>
                        <View style={[styles.modalBox, { maxHeight: '80%' }]}>
                            <Text style={styles.modalTitle}>📋 Skan tarixi</Text>
                            <ScrollView>
                                {history.length === 0 ? (
                                    <Text style={{ color: '#64748b', textAlign: 'center', padding: 20 }}>Hali skan yo'q</Text>
                                ) : history.map((h, i) => (
                                    <View key={i} style={styles.historyItem}>
                                        <View style={[styles.historyType, { backgroundColor: h.type === 'url' ? 'rgba(56,189,248,0.1)' : h.type === 'sms' ? 'rgba(168,85,247,0.1)' : 'rgba(245,158,11,0.1)' }]}>
                                            <Text style={{ color: h.type === 'url' ? '#38bdf8' : h.type === 'sms' ? '#a855f7' : '#f59e0b', fontSize: 10, fontWeight: '700' }}>{h.type.toUpperCase()}</Text>
                                        </View>
                                        <Text style={styles.historyData} numberOfLines={1}>{h.data}</Text>
                                        <Text style={[styles.historyScore, { color: h.is_safe ? '#22c55e' : '#ef4444' }]}>{h.score}%</Text>
                                        <Text style={{ fontSize: 16 }}>{h.is_safe ? '✅' : '🚨'}</Text>
                                    </View>
                                ))}
                            </ScrollView>
                            <TouchableOpacity onPress={() => setHistoryModal(false)} style={styles.modalClose}>
                                <Text style={{ color: '#64748b' }}>Yopish</Text>
                            </TouchableOpacity>
                        </View>
                    </View>
                </Modal>

                {/* QR SCANNER */}
                <Modal visible={isScanning} animationType="slide" onRequestClose={() => setIsScanning(false)}>
                    <View style={styles.scannerContainer}>
                        <CameraView style={StyleSheet.absoluteFillObject} onBarcodeScanned={handleBarCodeScanned} barcodeScannerSettings={{ barcodeTypes: ["qr"] }} />
                        <View style={styles.scannerOverlay}>
                            <Text style={styles.scannerText}>QR kodni ramkaga to'g'rilang</Text>
                            <View style={styles.scannerFrame} />
                            <TouchableOpacity style={styles.closeScannerButton} onPress={() => setIsScanning(false)}>
                                <Text style={styles.closeScannerText}>Yopish</Text>
                            </TouchableOpacity>
                        </View>
                    </View>
                </Modal>

            </SafeAreaView>
        </LinearGradient>
    );
}

const styles = StyleSheet.create({
    container: { flex: 1 },
    safeArea: { flex: 1 },
    scrollContent: { padding: 24, paddingTop: 40, paddingBottom: 40 },
    header: { alignItems: 'center', marginBottom: 20 },
    title: { fontSize: 30, fontWeight: '800', color: '#fff', marginTop: 12, letterSpacing: 1, textShadowColor: 'rgba(56,189,248,0.5)', textShadowOffset: { width: 0, height: 0 }, textShadowRadius: 20 },
    subtitle: { fontSize: 13, color: '#94a3b8', marginTop: 4, fontWeight: '500' },

    // AUTH BAR
    authBar: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', backgroundColor: 'rgba(17,30,51,0.9)', borderRadius: 14, padding: 10, marginBottom: 16, borderWidth: 1, borderColor: 'rgba(255,255,255,0.06)' },
    authUser: { flexDirection: 'row', alignItems: 'center', gap: 8 },
    authAvatar: { width: 34, height: 34, borderRadius: 10, backgroundColor: '#2563eb', alignItems: 'center', justifyContent: 'center' },
    authAvatarText: { color: '#fff', fontWeight: '700', fontSize: 14 },
    authName: { color: '#f1f5f9', fontWeight: '600', fontSize: 13 },
    authRole: { color: '#64748b', fontSize: 11, marginTop: 1 },
    guestText: { color: '#64748b', fontSize: 13, marginLeft: 6 },
    authBtns: { flexDirection: 'row', gap: 6 },
    loginBtn: { backgroundColor: '#2563eb', paddingHorizontal: 14, paddingVertical: 7, borderRadius: 8 },
    loginBtnText: { color: '#fff', fontWeight: '600', fontSize: 12 },
    logoutBtn: { backgroundColor: 'rgba(239,68,68,0.1)', paddingHorizontal: 12, paddingVertical: 7, borderRadius: 8, borderWidth: 1, borderColor: 'rgba(239,68,68,0.2)' },
    logoutBtnText: { color: '#ef4444', fontWeight: '600', fontSize: 12 },
    historyBtn: { backgroundColor: 'rgba(56,189,248,0.1)', paddingHorizontal: 12, paddingVertical: 7, borderRadius: 8, borderWidth: 1, borderColor: 'rgba(56,189,248,0.2)' },
    historyBtnText: { fontSize: 14 },

    // MODE
    modeSwitcher: { flexDirection: 'row', backgroundColor: 'rgba(30,41,59,0.8)', borderRadius: 16, padding: 4, marginBottom: 16 },
    modeButton: { flex: 1, paddingVertical: 11, alignItems: 'center', borderRadius: 12 },
    modeButtonActive: { backgroundColor: '#38bdf8' },
    modeText: { color: '#94a3b8', fontWeight: '600', fontSize: 13 },
    modeTextActive: { color: '#0f172a', fontWeight: 'bold' },

    // CARD
    card: { backgroundColor: 'rgba(30,41,59,0.7)', borderRadius: 24, padding: 20, borderWidth: 1, borderColor: 'rgba(255,255,255,0.1)', marginBottom: 20 },
    label: { color: '#e2e8f0', marginBottom: 12, fontSize: 13, fontWeight: '600', textTransform: 'uppercase', letterSpacing: 0.5 },

    // LOCK
    lockBox: { alignItems: 'center', padding: 20 },
    lockTitle: { color: '#f1f5f9', fontSize: 16, fontWeight: '700', marginTop: 12, marginBottom: 8, textAlign: 'center' },
    lockDesc: { color: '#64748b', fontSize: 13, textAlign: 'center', lineHeight: 20, marginBottom: 16 },
    lockBtn: { backgroundColor: '#2563eb', paddingHorizontal: 24, paddingVertical: 12, borderRadius: 12 },
    lockBtnText: { color: '#fff', fontWeight: '700', fontSize: 14 },

    // INPUT
    inputWrapper: { flexDirection: 'row', alignItems: 'center', backgroundColor: '#0f172a', borderRadius: 16, borderWidth: 1, borderColor: '#334155', marginBottom: 16, paddingHorizontal: 15 },
    inputIcon: { marginRight: 10 },
    input: { flex: 1, color: '#fff', paddingVertical: 15, fontSize: 15 },
    qrButton: { padding: 8 },
    fileContainer: { backgroundColor: '#0f172a', borderRadius: 16, borderWidth: 1, borderColor: '#334155', borderStyle: 'dashed', marginBottom: 16, height: 110, justifyContent: 'center' },
    fileButton: { alignItems: 'center', justifyContent: 'center', width: '100%', height: '100%' },
    fileButtonText: { color: '#e2e8f0', marginTop: 8, fontSize: 14, fontWeight: '500' },
    fileSizeText: { color: '#64748b', fontSize: 12, marginTop: 4 },

    // BUTTON
    button: { borderRadius: 16, overflow: 'hidden', shadowColor: '#3b82f6', shadowOffset: { width: 0, height: 8 }, shadowOpacity: 0.4, shadowRadius: 12, elevation: 10 },
    buttonGradient: { paddingVertical: 17, alignItems: 'center', justifyContent: 'center' },
    buttonContent: { flexDirection: 'row', alignItems: 'center' },
    buttonText: { color: '#fff', fontWeight: 'bold', fontSize: 17, letterSpacing: 1 },

    // RESULT
    resultCard: { backgroundColor: 'rgba(15,23,42,0.9)', borderRadius: 24, padding: 20, borderWidth: 2, marginBottom: 20 },
    safeBorder: { borderColor: '#22c55e', backgroundColor: 'rgba(34,197,94,0.05)' },
    dangerBorder: { borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.05)' },
    resultHeader: { flexDirection: 'row', alignItems: 'center', justifyContent: 'center', marginBottom: 12 },
    resultTitle: { fontSize: 26, fontWeight: 'bold', marginLeft: 10 },
    scoreText: { fontSize: 15, color: '#cbd5e1', textAlign: 'center', marginBottom: 14 },

    // PREVIEW
    previewBox: { backgroundColor: 'rgba(15,23,42,0.8)', borderRadius: 12, padding: 12, marginBottom: 14, borderWidth: 1, borderColor: 'rgba(255,255,255,0.06)' },
    previewSite: { color: '#38bdf8', fontSize: 11, fontWeight: '700', letterSpacing: 1, textTransform: 'uppercase', marginBottom: 6 },
    previewTitle: { color: '#f1f5f9', fontSize: 14, fontWeight: '600', marginBottom: 4, lineHeight: 20 },
    previewDesc: { color: '#64748b', fontSize: 12, lineHeight: 18 },

    // VT
    vtGrid: { flexDirection: 'row', gap: 6, marginBottom: 14 },
    vtBox: { flex: 1, backgroundColor: 'rgba(15,23,42,0.8)', borderRadius: 10, padding: 10, alignItems: 'center', borderWidth: 1, borderColor: 'rgba(255,255,255,0.06)' },
    vtNum: { fontSize: 20, fontWeight: '700' },
    vtLbl: { color: '#64748b', fontSize: 10, marginTop: 2 },

    // FILE INFO
    fileInfoBox: { backgroundColor: 'rgba(15,23,42,0.8)', borderRadius: 10, padding: 12, marginBottom: 12 },
    fileInfoRow: { color: '#94a3b8', fontSize: 13, marginBottom: 4 },
    fileInfoLabel: { color: '#64748b' },

    // CONCLUSION
    conclusionBox: { borderRadius: 10, padding: 12, marginBottom: 12, borderWidth: 1 },
    conclusionSafe: { backgroundColor: 'rgba(34,197,94,0.08)', borderColor: 'rgba(34,197,94,0.2)' },
    conclusionDanger: { backgroundColor: 'rgba(239,68,68,0.08)', borderColor: 'rgba(239,68,68,0.2)' },
    conclusionText: { fontSize: 13, fontWeight: '600', lineHeight: 20 },

    // THREATS
    threatsBox: { backgroundColor: 'rgba(0,0,0,0.2)', padding: 14, borderRadius: 12 },
    threatRow: { flexDirection: 'row', alignItems: 'flex-start', marginBottom: 8 },
    threatText: { color: '#fca5a5', marginLeft: 8, fontSize: 13, flex: 1, lineHeight: 18 },

    // MODAL
    modalOverlay: { flex: 1, backgroundColor: 'rgba(0,0,0,0.7)', justifyContent: 'flex-end' },
    modalBox: { backgroundColor: '#111e33', borderTopLeftRadius: 24, borderTopRightRadius: 24, padding: 24, borderTopWidth: 1, borderColor: 'rgba(255,255,255,0.06)' },
    modalLogo: { fontSize: 40, textAlign: 'center', marginBottom: 8 },
    modalTitle: { color: '#f1f5f9', fontSize: 18, fontWeight: '700', textAlign: 'center', marginBottom: 16 },
    modalTabs: { flexDirection: 'row', gap: 6, marginBottom: 16 },
    modalTab: { flex: 1, padding: 10, borderRadius: 10, borderWidth: 1, borderColor: 'rgba(255,255,255,0.06)', alignItems: 'center' },
    modalTabActive: { backgroundColor: '#2563eb', borderColor: 'transparent' },
    modalTabText: { color: '#64748b', fontWeight: '600', fontSize: 13 },
    modalTabTextActive: { color: '#fff' },
    modalInput: { backgroundColor: '#0d1526', borderWidth: 1, borderColor: 'rgba(255,255,255,0.08)', borderRadius: 12, color: '#f1f5f9', padding: 14, fontSize: 15, marginBottom: 12 },
    modalBtn: { backgroundColor: '#2563eb', borderRadius: 12, padding: 14, alignItems: 'center', marginTop: 4 },
    modalBtnText: { color: '#fff', fontWeight: '700', fontSize: 15 },
    modalClose: { alignItems: 'center', marginTop: 16, padding: 8 },
    otpInfo: { color: '#64748b', fontSize: 12, textAlign: 'center', marginBottom: 12, backgroundColor: '#0d1526', padding: 10, borderRadius: 8 },
    otpInput: { textAlign: 'center', fontSize: 24, letterSpacing: 10, fontWeight: '700' },

    // HISTORY
    historyItem: { flexDirection: 'row', alignItems: 'center', gap: 8, backgroundColor: 'rgba(15,23,42,0.8)', borderRadius: 12, padding: 12, marginBottom: 8 },
    historyType: { paddingHorizontal: 8, paddingVertical: 3, borderRadius: 99 },
    historyData: { flex: 1, color: '#64748b', fontSize: 12 },
    historyScore: { fontWeight: '700', fontSize: 13 },

    // QR
    scannerContainer: { flex: 1, backgroundColor: '#000' },
    scannerOverlay: { flex: 1, justifyContent: 'center', alignItems: 'center', backgroundColor: 'rgba(0,0,0,0.5)' },
    scannerText: { color: '#fff', fontSize: 18, marginBottom: 20, fontWeight: 'bold' },
    scannerFrame: { width: 250, height: 250, borderWidth: 2, borderColor: '#38bdf8', borderRadius: 20, backgroundColor: 'transparent' },
    closeScannerButton: { marginTop: 40, backgroundColor: '#ef4444', paddingVertical: 12, paddingHorizontal: 30, borderRadius: 10 },
    closeScannerText: { color: '#fff', fontSize: 16, fontWeight: 'bold' },
});