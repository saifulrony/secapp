'use client';

import { useState } from 'react';

type ScanStatus = 'idle' | 'scanning' | 'complete' | 'error';

interface ScanResult {
    target: string;
    headers: Record<string, { present: boolean; value: string | null }>;
    exposedFiles: Array<{ path: string; status: number | string; exists: boolean }>;
    serverInfo: { server: string; poweredBy: string };
    timestamp: string;
}

export default function Scanner() {
    const [url, setUrl] = useState('');
    const [status, setStatus] = useState<ScanStatus>('idle');
    const [results, setResults] = useState<ScanResult | null>(null);
    const [errorMessage, setErrorMessage] = useState('');

    const handleScan = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!url) return;

        setStatus('scanning');
        setResults(null);
        setErrorMessage('');

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url }),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Scan failed');
            }

            setResults(data);
            setStatus('complete');
        } catch (error) {
            setStatus('error');
            setErrorMessage(error instanceof Error ? error.message : 'An unknown error occurred');
        }
    };

    const getBadgeClass = (condition: boolean) => condition ? 'pass' : 'fail';
    const getBadgeText = (condition: boolean) => condition ? 'Present' : 'Missing';
    const getFileBadgeClass = (exists: boolean) => exists ? 'fail' : 'pass';
    const getFileBadgeText = (exists: boolean) => exists ? 'Exposed!' : 'Secure';

    return (
        <div className="glass-panel" style={{ maxWidth: '1000px', margin: '0 auto' }}>
            <form onSubmit={handleScan} className="scan-form">
                <div className="input-wrapper">
                    <input
                        type="text"
                        className="url-input"
                        placeholder="Enter target URL (e.g. example.com)"
                        value={url}
                        onChange={(e) => setUrl(e.target.value)}
                        disabled={status === 'scanning'}
                        aria-label="Target URL"
                        required
                    />
                </div>
                <button type="submit" className="scan-button" disabled={status === 'scanning' || !url}>
                    {status === 'scanning' ? (
                        <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <span className="loader"></span> Scanning...
                        </span>
                    ) : 'Scan Target'}
                </button>
            </form>

            {status === 'error' && (
                <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.2)', color: 'var(--error)', padding: '1rem', borderRadius: '0.5rem', marginBottom: '1.5rem', textAlign: 'center' }}>
                    {errorMessage}
                </div>
            )}

            {status === 'complete' && results && (
                <div className="results-grid">
                    {/* Section 1: Target Info */}
                    <div className="result-card" style={{ gridColumn: '1 / -1' }}>
                        <h3>
                            <svg style={{ width: '24px', height: '24px' }} fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                            Scan Summary
                        </h3>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '2rem' }}>
                            <div>
                                <div style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginBottom: '0.25rem' }}>Target</div>
                                <div style={{ fontWeight: 600, wordBreak: 'break-all' }}><a href={results.target} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--primary)' }}>{results.target}</a></div>
                            </div>
                            <div>
                                <div style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginBottom: '0.25rem' }}>Server</div>
                                <div style={{ fontWeight: 600 }}><span className="status-badge neutral">{results.serverInfo.server}</span></div>
                            </div>
                            <div>
                                <div style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginBottom: '0.25rem' }}>Powered By</div>
                                <div style={{ fontWeight: 600 }}><span className="status-badge neutral">{results.serverInfo.poweredBy}</span></div>
                            </div>
                            <div>
                                <div style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginBottom: '0.25rem' }}>Time</div>
                                <div style={{ fontWeight: 600 }}>{new Date(results.timestamp).toLocaleTimeString()}</div>
                            </div>
                        </div>
                    </div>

                    {/* Section 2: Security Headers */}
                    <div className="result-card">
                        <h3>
                            <svg style={{ width: '24px', height: '24px' }} fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                            Security Headers
                        </h3>
                        <div>
                            {Object.entries(results.headers).map(([header, data]) => (
                                <div key={header} className="list-item">
                                    <span style={{ fontSize: '0.875rem', fontWeight: 500 }}>{header}</span>
                                    <span className={`status-badge ${getBadgeClass(data.present)}`}>
                                        {getBadgeText(data.present)}
                                    </span>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Section 3: Exposed Files */}
                    <div className="result-card">
                        <h3>
                            <svg style={{ width: '24px', height: '24px' }} fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 7v8a2 2 0 002 2h6M8 7V5a2 2 0 012-2h4.586a1 1 0 01.707.293l4.414 4.414a1 1 0 01.293.707V15a2 2 0 01-2 2h-2M8 7H6a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2v-2"></path></svg>
                            Common Exposures (Basic)
                        </h3>
                        <div>
                            {results.exposedFiles.length > 0 ? results.exposedFiles.map((file, idx) => (
                                <div key={idx} className="list-item">
                                    <span style={{ fontSize: '0.875rem', fontFamily: 'monospace' }}>{file.path}</span>
                                    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                                        {file.status !== 'Error' && <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>[{file.status}]</span>}
                                        <span className={`status-badge ${getFileBadgeClass(file.exists)}`}>
                                            {getFileBadgeText(file.exists)}
                                        </span>
                                    </div>
                                </div>
                            )) : (
                                <div style={{ color: 'var(--text-muted)', fontSize: '0.875rem', padding: '1rem 0' }}>No files checked.</div>
                            )}
                        </div>
                        <div style={{ marginTop: '1rem', fontSize: '0.75rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                            Note: Evaluated based on simple HTTP status. Real-world scenarios may involve WAFs or soft 404s.
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
