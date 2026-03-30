'use client';

import { useState } from 'react';

type SimulationType = 'mysql' | 'ftp' | 'headers' | 'dmarc';
type Status = 'idle' | 'running' | 'success' | 'error';

interface SimulationResult {
    status: 'vulnerable' | 'secure';
    message: string;
    details?: string;
    impact?: string;
    error?: string;
}

export default function Tester() {
    const [target, setTarget] = useState('');
    const [activeSim, setActiveSim] = useState<SimulationType | null>(null);
    const [simStatus, setSimStatus] = useState<Status>('idle');
    const [result, setResult] = useState<SimulationResult | null>(null);

    const runSimulation = async (type: SimulationType) => {
        if (!target) return;
        setActiveSim(type);
        setSimStatus('running');
        setResult(null);

        try {
            const res = await fetch('/api/test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target, type }),
            });
            const data = await res.json();
            setResult(data);
            setSimStatus('success');
        } catch (e: any) {
            setSimStatus('error');
            setResult({ status: 'secure', message: 'Simulation Failed', error: e.message });
        }
    };

    return (
        <main>
            <h1>Vulnerability Impact Tester</h1>
            <p className="subtitle">
                Enter your website URL to safely simulate and visualize the real-world impact of your current security weaknesses.
            </p>

            <div className="glass-panel" style={{ maxWidth: '800px', marginBottom: '2rem' }}>
                <div className="scan-form">
                    <div className="input-wrapper">
                        <input
                            type="text"
                            className="url-input"
                            placeholder="Enter target (e.g. example.com)"
                            value={target}
                            onChange={(e) => setTarget(e.target.value)}
                            disabled={simStatus === 'running'}
                        />
                    </div>
                </div>
                
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                    <SimButton 
                        title="Database Probe (MySQL)" 
                        type="mysql" 
                        onRun={runSimulation} 
                        active={activeSim === 'mysql'} 
                        status={simStatus} 
                    />
                    <SimButton 
                        title="File Transfer Probe (FTP)" 
                        type="ftp" 
                        onRun={runSimulation} 
                        active={activeSim === 'ftp'} 
                        status={simStatus} 
                    />
                    <SimButton 
                        title="Web Header Simulation" 
                        type="headers" 
                        onRun={runSimulation} 
                        active={activeSim === 'headers'} 
                        status={simStatus} 
                    />
                    <SimButton 
                        title="Email Spoofing Check" 
                        type="dmarc" 
                        onRun={runSimulation} 
                        active={activeSim === 'dmarc'} 
                        status={simStatus} 
                    />
                </div>
            </div>

            {result && simStatus !== 'running' && (
                <div className="glass-panel" style={{ 
                    maxWidth: '800px', 
                    borderLeft: `6px solid ${result.status === 'vulnerable' ? 'var(--error)' : 'var(--success)'}`,
                    animation: 'fadeIn 0.4s ease-out'
                }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                        <h2 style={{ margin: 0, fontSize: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            {result.status === 'vulnerable' ? '⚠️ High Impact Detected' : '✅ Low Impact'}
                        </h2>
                        <span className={`status-badge ${result.status === 'vulnerable' ? 'fail' : 'pass'}`}>
                            {result.status === 'vulnerable' ? 'At Risk' : 'Secure'}
                        </span>
                    </div>

                    <div style={{ padding: '1rem', background: 'rgba(0,0,0,0.2)', borderRadius: '0.5rem', marginBottom: '1.5rem' }}>
                        <div style={{ fontWeight: 600, color: 'var(--text-muted)', fontSize: '0.875rem', marginBottom: '0.5rem', textTransform: 'uppercase' }}>
                            Evidence
                        </div>
                        <div style={{ fontFamily: 'monospace', fontSize: '1rem' }}>{result.details || result.message}</div>
                    </div>

                    {result.impact && (
                        <div>
                            <div style={{ fontWeight: 600, color: 'var(--text-muted)', fontSize: '0.875rem', marginBottom: '0.5rem', textTransform: 'uppercase' }}>
                                Potential Attacker Actions
                            </div>
                            <div style={{ lineHeight: 1.6, color: '#e2e8f0', fontSize: '1.125rem' }}>
                                {result.impact}
                            </div>
                        </div>
                    )}
                </div>
            )}
        </main>
    );
}

function SimButton({ title, type, onRun, active, status }: { title: string, type: SimulationType, onRun: (type: SimulationType) => void, active: boolean, status: Status }) {
    const isRunning = active && status === 'running';

    return (
        <button 
            className="glass-panel" 
            onClick={() => onRun(type)}
            disabled={status === 'running'}
            style={{ 
                padding: '1.5rem', 
                textAlign: 'left', 
                cursor: 'pointer',
                background: isRunning ? 'rgba(99, 102, 241, 0.2)' : 'rgba(30, 41, 59, 0.4)',
                border: isRunning ? '1px solid var(--primary)' : '1px solid var(--surface-border)',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.5rem',
                transition: 'all 0.2s ease'
            }}
        >
            <div style={{ fontWeight: 600, fontSize: '1rem' }}>{title}</div>
            <div style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
                {isRunning ? 'Running Simulation...' : 'Test Weakness'}
            </div>
            {isRunning && <div className="loader" style={{ marginTop: '0.5rem' }}></div>}
        </button>
    );
}
