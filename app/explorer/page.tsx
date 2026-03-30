'use client';

import { useState } from 'react';

type ExploreMethod = 'ftp' | 'http' | 'mysql';
type Status = 'idle' | 'running' | 'success' | 'error';

interface FileItem {
    name: string;
    type: 'file' | 'directory' | 'database' | 'table';
    size?: string;
    modified?: string;
}

interface ExploreResult {
    method: string;
    files: FileItem[];
    impact: string;
}

export default function Explorer() {
    const [target, setTarget] = useState('');
    const [method, setMethod] = useState<ExploreMethod>('ftp');
    const [path, setPath] = useState('/');
    const [status, setStatus] = useState<Status>('idle');
    const [result, setResult] = useState<ExploreResult | null>(null);
    const [error, setError] = useState('');

    const runExplore = async (currentPath = path) => {
        if (!target) return;
        setStatus('running');
        setError('');
        setResult(null);

        try {
            const res = await fetch('/api/explore', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target, method, path: currentPath }),
            });
            const data = await res.json();
            
            if (!res.ok) throw new Error(data.error || 'Exploration failed');
            
            setResult(data);
            setStatus('success');
        } catch (e: any) {
            setStatus('error');
            setError(e.message);
        }
    };

    const navigateTo = (newPath: string) => {
        setPath(newPath);
        runExplore(newPath);
    };

    return (
        <main>
            <h1>Vulnerability File Explorer</h1>
            <p className="subtitle">
                Access and browse the remote file system of a target website by exploiting exposed services like FTP or insecure directory indexes.
            </p>

            <div className="glass-panel" style={{ width: '100%', maxWidth: '1000px', marginBottom: '2rem' }}>
                <div className="scan-form">
                    <div className="input-wrapper">
                        <input
                            type="text"
                            className="url-input"
                            placeholder="Enter target (e.g. example.com)"
                            value={target}
                            onChange={(e) => setTarget(e.target.value)}
                            disabled={status === 'running'}
                        />
                    </div>
                    <select 
                        value={method} 
                        onChange={(e) => setMethod(e.target.value as ExploreMethod)}
                        style={{ background: 'rgba(15, 23, 42, 0.6)', color: 'white', border: '1px solid var(--surface-border)', borderRadius: '9999px', padding: '0 1rem' }}
                        disabled={status === 'running'}
                    >
                        <option value="ftp">FTP Exploration</option>
                        <option value="http">HTTP Indexer</option>
                        <option value="mysql">Database Browser (MySQL)</option>
                    </select>
                    <button className="scan-button" onClick={() => runExplore()} disabled={status === 'running' || !target}>
                        {status === 'running' ? 'Connecting...' : 'Explore'}
                    </button>
                </div>

                {error && (
                    <div style={{ color: 'var(--error)', padding: '1rem', background: 'rgba(239, 68, 68, 0.1)', borderRadius: '0.5rem', marginBottom: '1rem' }}>
                        {error}
                    </div>
                )}

                {result && (
                    <div className="result-card" style={{ background: 'transparent', border: 'none', padding: 0 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem', padding: '1rem', background: 'rgba(56, 189, 248, 0.1)', borderRadius: '0.5rem', borderLeft: '4px solid #38bdf8' }}>
                            <div>
                                <div style={{ fontSize: '0.75rem', color: '#38bdf8', textTransform: 'uppercase', fontWeight: 700, letterSpacing: '0.05em' }}>Active Connection</div>
                                <div style={{ fontWeight: 600 }}>{result.method}</div>
                            </div>
                            <div style={{ textAlign: 'right' }}>
                                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Impact</div>
                                <div style={{ color: 'var(--error)', fontSize: '0.875rem' }}>{result.impact}</div>
                            </div>
                        </div>

                        <div style={{ overflowX: 'auto' }}>
                            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                                <thead>
                                    <tr style={{ borderBottom: '1px solid var(--surface-border)' }}>
                                        <th style={{ padding: '1rem', color: 'var(--text-muted)', fontWeight: 500 }}>Name</th>
                                        <th style={{ padding: '1rem', color: 'var(--text-muted)', fontWeight: 500 }}>Type</th>
                                        <th style={{ padding: '1rem', color: 'var(--text-muted)', fontWeight: 500 }}>Size</th>
                                        <th style={{ padding: '1rem', color: 'var(--text-muted)', fontWeight: 500 }}>Action</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {result.files.length > 0 ? result.files.map((file, idx) => (
                                        <tr key={idx} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)', transition: 'background 0.2s' }} className="explorer-row">
                                            <td style={{ padding: '1rem', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                                                {file.type === 'directory' || file.type === 'database' ? '📁' : '📄'}
                                                <span style={{ fontWeight: 500 }}>{file.name}</span>
                                            </td>
                                            <td style={{ padding: '1rem' }}>
                                                <span className={`status-badge ${file.type === 'database' || file.type === 'table' ? 'warning' : 'neutral'}`}>{file.type}</span>
                                            </td>
                                            <td style={{ padding: '1rem', color: 'var(--text-muted)', fontSize: '0.875rem' }}>
                                                {file.size || '--'}
                                            </td>
                                            <td style={{ padding: '1rem' }}>
                                                {file.type === 'directory' && (
                                                    <button 
                                                        onClick={() => navigateTo(file.name)}
                                                        style={{ background: 'var(--primary)', border: 'none', color: 'white', padding: '0.4rem 1rem', borderRadius: '4px', cursor: 'pointer', fontSize: '0.75rem' }}
                                                    >
                                                        Open
                                                    </button>
                                                )}
                                                {file.type === 'file' && (
                                                    <button 
                                                        disabled
                                                        style={{ background: 'rgba(255,255,255,0.05)', border: 'none', color: 'var(--text-muted)', padding: '0.4rem 1rem', borderRadius: '4px', cursor: 'not-allowed', fontSize: '0.75rem' }}
                                                    >
                                                        Download
                                                    </button>
                                                )}
                                            </td>
                                        </tr>
                                    )) : (
                                        <tr>
                                            <td colSpan={4} style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                                                No files or folders found in this directory.
                                            </td>
                                        </tr>
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>
                )}
            </div>

            <style jsx>{`
                .explorer-row:hover {
                    background: rgba(255, 255, 255, 0.02);
                }
            `}</style>
        </main>
    );
}
