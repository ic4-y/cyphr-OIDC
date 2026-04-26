import React, { useState, useEffect } from 'react';
import { createRoot } from 'react-dom/client';

interface Identity {
    privateKey: string;
    publicKeyX: string;
    publicKeyY: string;
    thumbprint: string;
}

interface ExtensionStatus {
    wasmReady: boolean;
    hasKey: boolean;
    bridgeHost?: string;
}

interface Challenge {
    nonce: string;
    session: string;
}

type View = 'auth' | 'settings';

function sendMsg(action: string, params: Record<string, unknown> = {}): Promise<any> {
    return new Promise((resolve) => {
        chrome.runtime.sendMessage({ action, ...params }, resolve);
    });
}

function App() {
    const [status, setStatus] = useState<ExtensionStatus>({ wasmReady: false, hasKey: false });
    const [bridgeHost, setBridgeHost] = useState<string>('');
    const [challenge, setChallenge] = useState<Challenge | null>(null);
    const [message, setMessage] = useState('');
    const [messageType, setMessageType] = useState<'info' | 'success' | 'error'>('info');
    const [view, setView] = useState<View>('auth');
    const [identity, setIdentity] = useState<Identity | null>(null);
    const [importKey, setImportKey] = useState('');
    const [importError, setImportError] = useState('');
    const [wasmError, setWasmError] = useState<string>('');

    useEffect(() => {
        detectBridgeHost();
        const poll = setInterval(() => {
            sendMsg('GET_STATUS').then((response) => {
                if (!response || response.wasmReady) {
                    clearInterval(poll);
                }
                if (response) {
                    setStatus(response);
                    if (response.wasmReady) {
                        loadIdentity();
                    } else if (response.status && response.status.startsWith('error:')) {
                        clearInterval(poll);
                        setWasmError(response.status.replace('error: ', ''));
                    }
                }
            });
        }, 200);
        return () => clearInterval(poll);
    }, []);

    const checkStatus = () => {
        sendMsg('GET_STATUS').then((response) => {
            if (response) {
                setStatus(response);
                if (response.wasmReady) {
                    loadIdentity();
                } else if (response.status && response.status.startsWith('error:')) {
                    setWasmError(response.status.replace('error: ', ''));
                }
            }
        });
    };

    const detectBridgeHost = async () => {
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tab?.url) {
                const url = new URL(tab.url);
                setBridgeHost(url.origin);
            }
        } catch {
            const result = await chrome.storage.local.get(['bridgeHost']);
            if (result.bridgeHost) {
                setBridgeHost(result.bridgeHost);
            }
        }
    };

    const loadIdentity = async () => {
        const result = await chrome.storage.local.get(['privateKey']);
        if (result.privateKey) {
            const derived = await sendMsg('DERIVE_KEY', { privateKey: result.privateKey });
            if (derived.error) {
                console.error('[CyphrMask] Failed to derive key:', derived.error);
                return;
            }
            setIdentity({
                privateKey: result.privateKey,
                publicKeyX: derived.public_key_x,
                publicKeyY: derived.public_key_y,
                thumbprint: derived.thumbprint,
            });
        }
    };

    const generateNewKey = async () => {
        const result = await sendMsg('GENERATE_KEY');
        if (result.error) {
            setImportError(result.error);
            return;
        }
        const newIdentity: Identity = {
            privateKey: result.privateKey,
            publicKeyX: result.publicKeyX,
            publicKeyY: result.publicKeyY,
            thumbprint: result.thumbprint,
        };
        setIdentity(newIdentity);
        setStatus(prev => ({ ...prev, hasKey: true }));
    };

    const importKeyHex = async () => {
        setImportError('');
        const hex = importKey.trim();
        if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
            setImportError('Invalid key: must be 64 hex characters (32 bytes)');
            return;
        }
        const result = await sendMsg('IMPORT_KEY', { privateKey: hex });
        if (result.error) {
            setImportError(result.error);
            return;
        }
        const newIdentity: Identity = {
            privateKey: result.privateKey,
            publicKeyX: result.publicKeyX,
            publicKeyY: result.publicKeyY,
            thumbprint: result.thumbprint,
        };
        setIdentity(newIdentity);
        setStatus(prev => ({ ...prev, hasKey: true }));
        setImportKey('');
    };

    const openSettings = () => {
        chrome.runtime.openOptionsPage();
    };

    const copyBridgeUserJSON = () => {
        if (!identity) return;
        const pubKey = '04' + identity.publicKeyX + identity.publicKeyY;
        const json = `{"${identity.thumbprint}":{"public_key":"${pubKey}","email":"user@example.com"}}`;
        navigator.clipboard.writeText(`BRIDGE_USERS='${json}'`);
        setMessage('Bridge user JSON copied!');
        setMessageType('success');
    };

    const exportIdentity = () => {
        if (!identity) return;
        const backup = {
            principal_root: identity.thumbprint,
            public_key_x: identity.publicKeyX,
            public_key_y: identity.publicKeyY,
            private_key: identity.privateKey,
            algorithm: 'P-256',
            format: 'cyphr-backup-v1',
            warning: 'Anyone with this file can impersonate you. Keep it secure.',
        };
        const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `cyphrmask-${identity.thumbprint.substring(0, 8)}-backup.json`;
        a.click();
        URL.revokeObjectURL(url);
    };

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
    };

    const fetchChallenge = async () => {
        try {
            const resp = await fetch(`${bridgeHost}/api/challenge`);
            if (!resp.ok) throw new Error('Failed to fetch challenge');
            const data = await resp.json();
            setChallenge(data);
            setMessage('Challenge received. Click Approve to sign.');
            setMessageType('info');
        } catch (err) {
            setMessage('Failed to fetch challenge: ' + (err as Error).message);
            setMessageType('error');
        }
    };

    const approveChallenge = async () => {
        if (!challenge) return;
        setMessage('Signing challenge...');
        setMessageType('info');
        try {
            const resp = await sendMsg('REQUEST_SIGNATURE', { nonce: challenge.nonce });
            if (resp?.error) throw new Error(resp.error);
            if (!resp?.coz) throw new Error('No signature received');
            const resp2 = await fetch(`${bridgeHost}/api/verify`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: resp.coz
            });
            if (!resp2.ok) throw new Error(await resp2.text());
            const data = await resp2.json();
            setMessage(`Authenticated as ${data.email}`);
            setMessageType('success');
        } catch (err) {
            setMessage('Failed: ' + (err as Error).message);
            setMessageType('error');
        }
    };

    if (!status.wasmReady) {
        if (wasmError) {
            return (
                <div className="container">
                    <h2>CyphrMask</h2>
                    <p className="subtitle">Wasm Initialization Failed</p>
                    <div className="message error">{wasmError}</div>
                    <p style={{ marginTop: '0.5rem', fontSize: '0.75rem', color: '#64748b' }}>
                        Check the browser console for details.
                    </p>
                </div>
            );
        }
        return (
            <div className="container">
                <div className="spinner" />
                <p>Initializing crypto module...</p>
            </div>
        );
    }

    if (!status.hasKey && !identity) {
        return (
            <div className="container">
                <h2>CyphrMask</h2>
                <p className="subtitle">Set up your identity</p>
                <button className="btn-primary" onClick={generateNewKey}>
                    Generate New Key
                </button>
                <div className="divider">or import</div>
                <input
                    type="text"
                    className="text-input"
                    placeholder="Paste 64-char hex private key"
                    value={importKey}
                    onChange={e => setImportKey(e.target.value)}
                />
                <button className="btn-secondary" onClick={importKeyHex}>
                    Import Private Key
                </button>
                <button className="btn-secondary full-width" onClick={openSettings}>
                    Import Backup File (opens settings)
                </button>
                {importError && <div className="message error">{importError}</div>}
            </div>
        );
    }

    return (
        <div className="container">
            <div className="header">
                <h2>CyphrMask</h2>
                <div className="tabs">
                    <button className={`tab ${view === 'auth' ? 'active' : ''}`} onClick={() => setView('auth')}>
                        Auth
                    </button>
                    <button className={`tab ${view === 'settings' ? 'active' : ''}`} onClick={() => setView('settings')}>
                        Settings
                    </button>
                </div>
            </div>

            {view === 'auth' && (
                <div className="auth-view">
                    <p className="subtitle">Authentication Request{bridgeHost && ` — ${bridgeHost}`}</p>
                    {challenge && (
                        <div className="challenge-box">
                            <label>Nonce</label>
                            <code>{challenge.nonce.substring(0, 16)}...</code>
                        </div>
                    )}
                    {!challenge && (
                        <button className="btn-primary" onClick={fetchChallenge}>
                            Fetch Challenge
                        </button>
                    )}
                    {challenge && (
                        <button className="btn-approve" onClick={approveChallenge}>
                            Approve
                        </button>
                    )}
                    {message && (
                        <div className={`message ${messageType}`}>
                            {message}
                        </div>
                    )}
                </div>
            )}

            {view === 'settings' && identity && (
                <div className="settings-view">
                    <div className="setting-group">
                        <label>Principal Root (tmb)</label>
                        <div className="value-row">
                            <code className="value">{identity.thumbprint}</code>
                            <button className="btn-icon" onClick={() => copyToClipboard(identity.thumbprint)} title="Copy">
                                📋
                            </button>
                        </div>
                    </div>

                    <div className="setting-group">
                        <label>Public Key X</label>
                        <div className="value-row">
                            <code className="value">{identity.publicKeyX}</code>
                            <button className="btn-icon" onClick={() => copyToClipboard(identity.publicKeyX)} title="Copy">
                                📋
                            </button>
                        </div>
                    </div>

                    <div className="setting-group">
                        <label>Public Key Y</label>
                        <div className="value-row">
                            <code className="value">{identity.publicKeyY}</code>
                            <button className="btn-icon" onClick={() => copyToClipboard(identity.publicKeyY)} title="Copy">
                                📋
                            </button>
                        </div>
                    </div>

                    <div className="divider" />

                    <button className="btn-secondary full-width" onClick={copyBridgeUserJSON} title="Copy BRIDGE_USERS JSON">
                        Copy Bridge User JSON
                    </button>

                    <button className="btn-secondary full-width" onClick={exportIdentity}>
                        Export Identity Backup
                    </button>

                    <div className="divider">or import</div>

                    <input
                        type="text"
                        className="text-input"
                        placeholder="Paste 64-char hex private key"
                        value={importKey}
                        onChange={e => { setImportKey(e.target.value); setImportError(''); }}
                    />
                    <button className="btn-secondary full-width" onClick={importKeyHex}>
                        Import Private Key
                    </button>
                    <button className="btn-secondary full-width" onClick={openSettings}>
                        Import Backup File (opens settings)
                    </button>
                    {importError && <div className="message error">{importError}</div>}
                    {message && (
                        <div className={`message ${messageType}`}>
                            {message}
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

const root = createRoot(document.getElementById('root')!);
root.render(<App />);

export default App;
