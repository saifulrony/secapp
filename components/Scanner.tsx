'use client';

import { useState } from 'react';

type ScanStatus = 'idle' | 'scanning' | 'complete' | 'error';

interface ScanResult {
    target: string;
    headers: Record<string, { present: boolean; value: string | null }>;
    exposedFiles: Array<{ path: string; status: number | string; exists: boolean }>;
    serverInfo: { server: string; poweredBy: string };
    cookieFlags: Array<{ name: string; secure: boolean; httpOnly: boolean; sameSite: string }>;
    ssl: { valid: boolean; issuer?: string; validFrom?: string; validTo?: string; error?: string };
    ports: Array<{ port: number; service: string; open: boolean; reason?: string }>;
    dnsRecords: { spf: boolean; dmarc: boolean };
    wafDetected: boolean | null;
    fingerprint: string[];
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
            const apiUrl = `${window.location.origin}/api/scan`;
            const response = await fetch(apiUrl, {
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
                    {/* Section 4: Cookie Security Flags */}
                    <div className="result-card">
                        <h3>
                            <svg style={{ width: '24px', height: '24px' }} fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
                            Cookie Flags
                        </h3>
                        <div>
                            {results.cookieFlags.length > 0 ? results.cookieFlags.map((cookie, idx) => (
                                <div key={idx} className="list-item" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: '0.5rem' }}>
                                    <span style={{ fontSize: '0.875rem', fontWeight: 600 }}>{cookie.name}</span>
                                    <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                                        <span className={`status-badge ${getBadgeClass(cookie.secure)}`}>
                                            Secure: {cookie.secure ? 'Yes' : 'No'}
                                        </span>
                                        <span className={`status-badge ${getBadgeClass(cookie.httpOnly)}`}>
                                            HttpOnly: {cookie.httpOnly ? 'Yes' : 'No'}
                                        </span>
                                        <span className="status-badge neutral">
                                            SameSite: {cookie.sameSite.split(';')[0]}
                                        </span>
                                    </div>
                                </div>
                            )) : (
                                <div style={{ color: 'var(--text-muted)', fontSize: '0.875rem', padding: '1rem 0' }}>No cookies returned.</div>
                            )}
                        </div>
                    </div>

                    {/* Section 5: SSL/TLS Certificate */}
                    <div className="result-card">
                        <h3>
                            <svg style={{ width: '24px', height: '24px' }} fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                            SSL / TLS Certificate
                        </h3>
                        <div>
                            {results.ssl ? (
                                results.ssl.valid ? (
                                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                                        <div className="list-item">
                                            <span style={{ fontSize: '0.875rem', fontWeight: 500 }}>Status</span>
                                            <span className="status-badge pass">Valid</span>
                                        </div>
                                        <div className="list-item">
                                            <span style={{ fontSize: '0.875rem', fontWeight: 500 }}>Issuer</span>
                                            <span style={{ fontSize: '0.875rem', textAlign: 'right', color: 'var(--text-muted)' }}>{results.ssl.issuer}</span>
                                        </div>
                                        <div className="list-item" style={{ flexDirection: 'column', alignItems: 'flex-start', borderBottom: 'none' }}>
                                            <span style={{ fontSize: '0.875rem', fontWeight: 500, marginBottom: '0.25rem' }}>Expires</span>
                                            <span style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>{new Date(results.ssl.validTo || '').toLocaleDateString()}</span>
                                        </div>
                                    </div>
                                ) : (
                                    <div className="list-item">
                                        <span style={{ fontSize: '0.875rem', fontWeight: 500 }}>Status</span>
                                        <span className="status-badge fail">Invalid / Error</span>
                                    </div>
                                )
                            ) : (
                                <div style={{ color: 'var(--text-muted)', fontSize: '0.875rem', padding: '1rem 0' }}>HTTP site or SSL check not available locally.</div>
                            )}
                        </div>
                    </div>

                    {/* Section 6: Open Ports */}
                    <div className="result-card">
                        <h3>
                            <svg style={{ width: '24px', height: '24px' }} fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"></path></svg>
                            Port Scanning (Top 5)
                        </h3>
                        <div>
                            {results.ports.length > 0 ? results.ports.map((port, idx) => (
                                <div key={idx} className="list-item">
                                    <span style={{ fontSize: '0.875rem', fontWeight: 500 }}>{port.port} / {port.service}</span>
                                    <span className={`status-badge ${getFileBadgeClass(port.open)}`}>
                                        {port.open ? 'OPEN' : 'Closed'}
                                    </span>
                                </div>
                            )) : (
                                <div style={{ color: 'var(--text-muted)', fontSize: '0.875rem', padding: '1rem 0' }}>Port scanning failed or unavailable.</div>
                            )}
                        </div>
                    </div>
                    {/* Section 7: DNS Email Security */}
                    <div className="result-card">
                        <h3>
                            <svg style={{ width: '24px', height: '24px' }} fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>
                            Email Security (DNS)
                        </h3>
                        <div>
                            <div className="list-item">
                                <span style={{ fontSize: '0.875rem', fontWeight: 500 }}>SPF Record</span>
                                <span className={`status-badge ${getBadgeClass(results.dnsRecords.spf)}`}>
                                    {getBadgeText(results.dnsRecords.spf)}
                                </span>
                            </div>
                            <div className="list-item">
                                <span style={{ fontSize: '0.875rem', fontWeight: 500 }}>DMARC Record</span>
                                <span className={`status-badge ${getBadgeClass(results.dnsRecords.dmarc)}`}>
                                    {getBadgeText(results.dnsRecords.dmarc)}
                                </span>
                            </div>
                        </div>
                    </div>

                    {/* Section 8: WAF & Tech Fingerprint */}
                    <div className="result-card" style={{ gridColumn: '1 / -1' }}>
                        <h3>
                            <svg style={{ width: '24px', height: '24px' }} fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"></path></svg>
                            Deep Fingerprinting & WAF
                        </h3>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>
                            <div>
                                <h4 style={{ fontSize: '0.875rem', color: 'var(--text-muted)', marginBottom: '1rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>WAF Detection</h4>
                                <div className="list-item" style={{ borderBottom: 'none', padding: 0 }}>
                                    <span style={{ fontSize: '0.875rem', fontWeight: 500 }}>Active Firewall</span>
                                    {results.wafDetected === null ? (
                                        <span className="status-badge neutral">Unknown</span>
                                    ) : (
                                        <span className={`status-badge ${results.wafDetected ? 'pass' : 'fail'}`}>
                                            {results.wafDetected ? 'Detected' : 'Not Detected'}
                                        </span>
                                    )}
                                </div>
                                <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>Tests basic SQLi/LFI payloads against the public endpoint.</p>
                            </div>
                            <div>
                                <h4 style={{ fontSize: '0.875rem', color: 'var(--text-muted)', marginBottom: '1rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Tech Stack (Frontend)</h4>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                                    {results.fingerprint.length > 0 ? results.fingerprint.map((tech, idx) => (
                                        <span key={idx} className="status-badge neutral" style={{ background: 'rgba(56, 189, 248, 0.1)', color: '#38bdf8', border: '1px solid rgba(56, 189, 248, 0.2)' }}>
                                            {tech}
                                        </span>
                                    )) : (
                                        <span style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>No common frameworks identified natively.</span>
                                    )}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
