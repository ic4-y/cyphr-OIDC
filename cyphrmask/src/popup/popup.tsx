import React, { useState, useEffect } from 'react';
import { createRoot } from 'react-dom/client';

interface ExtensionStatus {
    wasmReady: boolean;
    hasKey: boolean;
}

interface Challenge {
    nonce: string;
    session: string;
}

const BRIDGE_URL = 'http://localhost:8080';

function App() {
    const [status, setStatus] = useState<ExtensionStatus>({ wasmReady: false, hasKey: false });
    const [challenge, setChallenge] = useState<Challenge | null>(null);
    const [message, setMessage] = useState('');
    const [messageType, setMessageType] = useState<'info' | 'success' | 'error'>('info');

    useEffect(() => {
        checkStatus();
    }, []);

    const checkStatus = () => {
        chrome.runtime.sendMessage({ action: 'GET_STATUS' }, (response) => {
            if (response) {
                setStatus(response);
            }
        });
    };

    const fetchChallenge = async () => {
        try {
            const resp = await fetch(`${BRIDGE_URL}/api/challenge`);
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
            const resp = await chrome.runtime.sendMessage({
                action: 'REQUEST_SIGNATURE',
                nonce: challenge.nonce
            });

            if (resp?.error) {
                throw new Error(resp.error);
            }

            if (!resp?.coz) {
                throw new Error('No signature received');
            }

            await submitSignature(resp.coz);
        } catch (err) {
            setMessage('Signing failed: ' + (err as Error).message);
            setMessageType('error');
        }
    };

    const submitSignature = async (coz: string) => {
        setMessage('Submitting to bridge...');
        setMessageType('info');

        try {
            const resp = await fetch(`${BRIDGE_URL}/api/verify`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: coz
            });

            if (!resp.ok) {
                const text = await resp.text();
                throw new Error(text);
            }

            const data = await resp.json();
            setMessage(`Authenticated as ${data.email}`);
            setMessageType('success');
        } catch (err) {
            setMessage('Verification failed: ' + (err as Error).message);
            setMessageType('error');
        }
    };

    if (!status.wasmReady) {
        return (
            <div className="container">
                <div className="spinner"></div>
                <p>Initializing crypto module...</p>
            </div>
        );
    }

    if (!status.hasKey) {
        return (
            <div className="container">
                <h2>CyphrMask</h2>
                <p className="subtitle">No key configured</p>
                <p>Run the key setup wizard to generate or import your Level 1 principal key.</p>
            </div>
        );
    }

    return (
        <div className="container">
            <h2>CyphrMask</h2>
            <p className="subtitle">Authentication Request</p>

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
    );
}

const root = createRoot(document.getElementById('root')!);
root.render(<App />);

export default App;
