import React, { useState, useEffect } from 'react';
import { createRoot } from 'react-dom/client';

interface Identity {
    privateKey: string;
    publicKeyX: string;
    publicKeyY: string;
    thumbprint: string;
}

function sendMsg(action: string, params: Record<string, unknown> = {}): Promise<any> {
    return new Promise((resolve) => {
        chrome.runtime.sendMessage({ action, ...params }, resolve);
    });
}

function App() {
    const [wasmReady, setWasmReady] = useState(false);
    const [hasKey, setHasKey] = useState(false);
    const [identity, setIdentity] = useState<Identity | null>(null);
    const [importKey, setImportKey] = useState('');
    const [importError, setImportError] = useState('');
    const [wasmError, setWasmError] = useState<string>('');
    const [statusMessage, setStatusMessage] = useState('');

    useEffect(() => {
        const poll = setInterval(() => {
            sendMsg('GET_STATUS').then((response) => {
                if (!response || response.wasmReady) {
                    clearInterval(poll);
                }
                if (response) {
                    setWasmReady(response.wasmReady);
                    setHasKey(response.hasKey);
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
        setImportError('');
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
        setHasKey(true);
        setStatusMessage('New key generated successfully.');
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
        setHasKey(true);
        setImportKey('');
        setStatusMessage('Key imported successfully.');
    };

    const importKeyFile = (file: File) => {
        setImportError('');
        const reader = new FileReader();
        reader.onload = async () => {
            try {
                const data = JSON.parse(reader.result as string);
                if (!data.private_key) {
                    setImportError('Invalid backup: missing private_key');
                    return;
                }
                const result = await sendMsg('IMPORT_KEY', { privateKey: data.private_key });
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
                setHasKey(true);
                setStatusMessage('Backup imported successfully.');
            } catch (err) {
                console.error('[CyphrMask] Failed to import backup:', err);
                setImportError('Invalid backup file');
            }
        };
        reader.readAsText(file);
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
        setStatusMessage('Identity exported.');
    };

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
    };

    const copyBridgeUserJSON = () => {
        if (!identity) return;
        const pubKey = '04' + identity.publicKeyX + identity.publicKeyY;
        const json = `{"${identity.thumbprint}":{"public_key":"${pubKey}","email":"user@example.com"}}`;
        navigator.clipboard.writeText(`BRIDGE_USERS='${json}'`);
        setStatusMessage('Bridge user JSON copied to clipboard.');
    };

    if (!wasmReady) {
        if (wasmError) {
            return (
                <div className="container">
                    <h2>CyphrMask Settings</h2>
                    <p className="subtitle">Wasm Initialization Failed</p>
                    <div className="message error">{wasmError}</div>
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

    if (!hasKey && !identity) {
        return (
            <div className="container">
                <h2>CyphrMask Settings</h2>
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
                <label className="file-label">
                    <input
                        type="file"
                        accept=".json"
                        onChange={e => e.target.files?.[0] && importKeyFile(e.target.files[0])}
                    />
                    Import Backup File
                </label>
                {importError && <div className="message error">{importError}</div>}
            </div>
        );
    }

    return (
        <div className="container">
            <h2>CyphrMask Settings</h2>

            {statusMessage && <div className="message success">{statusMessage}</div>}

            <div className="setting-group">
                <label>Principal Root (tmb)</label>
                <div className="value-row">
                    <code className="value">{identity?.thumbprint}</code>
                    <button className="btn-icon" onClick={() => copyToClipboard(identity!.thumbprint)} title="Copy">
                        📋
                    </button>
                </div>
            </div>

            <div className="setting-group">
                <label>Public Key X</label>
                <div className="value-row">
                    <code className="value">{identity?.publicKeyX}</code>
                    <button className="btn-icon" onClick={() => copyToClipboard(identity!.publicKeyX)} title="Copy">
                        📋
                    </button>
                </div>
            </div>

            <div className="setting-group">
                <label>Public Key Y</label>
                <div className="value-row">
                    <code className="value">{identity?.publicKeyY}</code>
                    <button className="btn-icon" onClick={() => copyToClipboard(identity!.publicKeyY)} title="Copy">
                        📋
                    </button>
                </div>
            </div>

            <div className="divider" />

            <div className="setting-group">
                <label>Bridge User JSON</label>
                <p style={{ fontSize: '0.8rem', color: '#64748b', marginBottom: '0.5rem' }}>
                    Click 📋 to copy — paste into <code>.env</code> at project root
                </p>
                <div className="value-row">
                    <code className="value" style={{ fontSize: '0.65rem', wordBreak: 'break-all' }}>
                        {identity && `BRIDGE_USERS='{"${identity.thumbprint}":{"public_key":"04${identity.publicKeyX}${identity.publicKeyY}","email":"user@example.com"}}'`}
                    </code>
                    <button className="btn-icon" onClick={copyBridgeUserJSON} title="Copy">
                        📋
                    </button>
                </div>
            </div>

            <div className="divider" />

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
            <label className="file-label">
                <input
                    type="file"
                    accept=".json"
                    onChange={e => { e.target.files?.[0] && importKeyFile(e.target.files[0]); setImportError(''); }}
                />
                Import Backup File
            </label>
            {importError && <div className="message error">{importError}</div>}

            <div className="divider" />

            <button className="btn-secondary full-width" onClick={generateNewKey}>
                Generate New Key (replaces current)
            </button>
        </div>
    );
}

const root = createRoot(document.getElementById('root')!);
root.render(<App />);

export default App;
