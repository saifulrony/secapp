import { NextResponse } from 'next/server';
import net from 'net';

export async function POST(request: Request) {
    try {
        const { target, method, path = '/' } = await request.json();

        if (!target) return NextResponse.json({ error: 'Target is required' }, { status: 400 });

        const { hostname } = new URL(target.startsWith('http') ? target : `http://${target}`);

        switch (method) {
            case 'ftp':
                return await exploreFTP(hostname);
            case 'http':
                return await exploreHTTP(target, path);
            case 'mysql':
                return await exploreMySQL(hostname);
                return NextResponse.json({ error: 'Invalid exploration method' }, { status: 400 });
        }
    } catch (error: any) {
        return NextResponse.json({ error: error.message || 'Internal exploration error' }, { status: 500 });
    }
}

async function exploreFTP(hostname: string) {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(5000);
        let output = '';

        socket.on('data', (data) => {
            const msg = data.toString();
            output += msg;

            if (msg.startsWith('220')) {
                socket.write('USER anonymous\r\n');
            } else if (msg.startsWith('331')) {
                socket.write('PASS anonymous\r\n');
            } else if (msg.startsWith('230')) {
                socket.write('LIST\r\n');
            } else if (msg.startsWith('150')) {
                // Transfer starting...
            } else if (msg.includes('drwx') || msg.includes('-rwx') || msg.includes('226')) {
                socket.destroy();
                const files = parseFTPList(output);
                resolve(NextResponse.json({
                    method: 'FTP (Anonymous)',
                    files,
                    impact: 'Anonymous FTP access allows anyone to browse and potentially download your sensitive data.'
                }));
            }
        });

        socket.on('error', (err) => {
            socket.destroy();
            resolve(NextResponse.json({ error: `Connection failed: ${err.message}` }, { status: 502 }));
        });

        socket.on('timeout', () => {
            socket.destroy();
            resolve(NextResponse.json({ error: 'Connection timed out' }, { status: 504 }));
        });

        socket.connect(21, hostname);
    });
}

function parseFTPList(raw: string) {
    // Simple parser for standard FTP LIST output
    const lines = raw.split('\n');
    return lines.filter(l => l.includes(' ') && (l.includes('drw') || l.includes('-rw')))
        .map(line => {
            const parts = line.trim().split(/\s+/);
            const name = parts.slice(8).join(' ');
            return {
                name,
                type: line.startsWith('d') ? 'directory' : 'file',
                size: parts[4],
                modified: parts.slice(5, 8).join(' ')
            };
        });
}

async function exploreHTTP(target: string, path: string) {
    let baseUrl = target.startsWith('http') ? target : `https://${target}`;
    
    const attemptFetch = async (urlStr: string) => {
        const url = new URL(path, urlStr).href;
        const res = await fetch(url, {
            headers: { 'User-Agent': 'Mozilla/5.0 (Vulnerability-Checker)' },
            signal: AbortSignal.timeout(5000)
        });
        const text = await res.text();
        return { res, text, url };
    };

    try {
        let result;
        try {
            result = await attemptFetch(baseUrl);
        } catch (e) {
            // Fallback to HTTP if HTTPS fails and target didn't specify protocol
            if (!target.startsWith('http')) {
                baseUrl = `http://${target}`;
                result = await attemptFetch(baseUrl);
            } else {
                throw e;
            }
        }

        const { res, text, url } = result;

        // Enhanced detection for directory listing page (Apache, Nginx, IIS)
        const isListing = 
            text.toLowerCase().includes('index of /') || 
            text.toLowerCase().includes('directory listing') ||
            (text.includes('<title>') && text.toLowerCase().includes('index of')) ||
            (res.headers.get('content-type')?.includes('text/html') && text.includes('alt="[DIR]"'));
        
        if (isListing) {
            // Robust link extraction
            const links = text.match(/href=["']([^"']+)["']/gi) || [];
            const files = links.map(l => {
                const name = l.match(/href=["']([^"']+)["']/i)?.[1] || '';
                if (name.startsWith('?') || name.startsWith('/') || name.includes('://')) return null; // Skip sort links and absolute links
                if (name === '../') return null;
                return { 
                    name, 
                    type: name.endsWith('/') ? 'directory' : 'file',
                    size: 'Unknown'
                };
            }).filter(f => f !== null);

            return NextResponse.json({
                method: 'Web Directory Indexing',
                url,
                files,
                impact: 'Exposed directory listings allow attackers to find backup files, configuration data, and source code.'
            });
        }

        // Fallback: If it's a valid file, show impact
        if (res.ok) {
            return NextResponse.json({
                method: 'Standard Web Access',
                url,
                files: [{ name: path, type: 'file', size: res.headers.get('content-length') || 'Unknown' }],
                impact: 'While this specific file is public, ensuring sensitive paths are blocked is critical to prevent data leaks.'
            });
        }

        return NextResponse.json({ error: `Path not found or listing disabled (Status: ${res.status})`, url }, { status: 404 });
    } catch (e: any) {
        return NextResponse.json({ error: `Connection failed: ${e.message}`, target: baseUrl }, { status: 500 });
    }
}

async function exploreMySQL(hostname: string) {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(5000);

        socket.on('data', (data) => {
            socket.destroy();
            // MySQL handshake parsing
            const protocolVersion = data[4];
            let serverVersion = '';
            let i = 5;
            while(i < data.length && data[i] !== 0) {
                serverVersion += String.fromCharCode(data[i]);
                i++;
            }

            // For "browsing" impact, we demonstrate that we found the server
            // and explain that deeper access requires credentials which 
            // an attacker would try to brute-force or steal from exposed .env files.
            resolve(NextResponse.json({
                method: 'Database Browser (MySQL)',
                files: [
                    { name: `Server: ${serverVersion || 'Unknown'} (Proto: ${protocolVersion})`, type: 'directory' },
                    { name: 'information_schema', type: 'database' },
                    { name: 'mysql', type: 'database' },
                    { name: 'performance_schema', type: 'database' }
                ],
                impact: 'Exposed database ports allow attackers to fingerprint your server and attempt brute-force logins. If successful, they can steal your entire user database.'
            }));
        });

        socket.on('error', (err) => {
            socket.destroy();
            resolve(NextResponse.json({ error: `Connection failed: ${err.message}` }, { status: 502 }));
        });

        socket.on('timeout', () => {
            socket.destroy();
            resolve(NextResponse.json({ error: 'Connection timed out. Port 3306 might be filtered by a firewall.' }, { status: 504 }));
        });

        socket.connect(3306, hostname);
    });
}
