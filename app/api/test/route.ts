import { NextResponse } from 'next/server';
import net from 'net';

export async function POST(request: Request) {
    try {
        const { target, type } = await request.json();

        if (!target) return NextResponse.json({ error: 'Target is required' }, { status: 400 });

        const { hostname } = new URL(target.startsWith('http') ? target : `http://${target}`);

        switch (type) {
            case 'mysql':
                return await probeMySQL(hostname);
            case 'ftp':
                return await probeFTP(hostname);
            case 'headers':
                return await probeHeaders(target.startsWith('http') ? target : `https://${target}`);
            case 'dmarc':
                return await probeDMARC(hostname);
            default:
                return NextResponse.json({ error: 'Invalid simulation type' }, { status: 400 });
        }
    } catch (error: any) {
        return NextResponse.json({ error: error.message || 'Internal simulation error' }, { status: 500 });
    }
}

async function probeMySQL(hostname: string) {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        // Increase timeout for remote servers
        socket.setTimeout(5000);

        let dataReceived = false;

        socket.on('data', (data) => {
            if (dataReceived) return;
            dataReceived = true;
            socket.destroy();
            
            // MySQL handshake parsing
            const protocolVersion = data[4];
            let serverVersion = '';
            let i = 5;
            while(i < data.length && data[i] !== 0) {
                serverVersion += String.fromCharCode(data[i]);
                i++;
            }

            resolve(NextResponse.json({
                status: 'vulnerable',
                message: 'Database Port Exposed!',
                details: `Established connection to MySQL. Protocol: ${protocolVersion}, Server Version: ${serverVersion || 'Unknown'}`,
                impact: 'An attacker can attempt to brute-force this database or exploit known vulnerabilities in this specific server version.'
            }));
        });

        socket.on('error', (err) => {
            socket.destroy();
            resolve(NextResponse.json({ 
                status: 'secure', 
                message: 'Connection Refused/Error', 
                details: err.message,
                impact: 'Port appears closed or filtered. No direct impact detected.' 
            }));
        });

        socket.on('timeout', () => {
            socket.destroy();
            resolve(NextResponse.json({ 
                status: 'secure', 
                message: 'Connection Timeout', 
                details: 'Target did not respond in time on port 3306.',
                impact: 'Likely protected by a firewall or the port is closed.' 
            }));
        });

        // Ensure we try both IPv4 and IPv6 if host supports it
        socket.connect(3306, hostname);
    });
}

async function probeFTP(hostname: string) {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(3000);

        socket.on('data', (data) => {
            socket.destroy();
            const banner = data.toString().trim();
            resolve(NextResponse.json({
                status: 'vulnerable',
                message: 'FTP Service Exposed!',
                details: `Banner received: ${banner}`,
                impact: 'Unencrypted FTP allows attackers to intercept credentials or attempt brute-force attacks to gain file-system access.'
            }));
        });

        socket.on('error', (err) => {
            socket.destroy();
            resolve(NextResponse.json({ status: 'secure', message: 'Connection Error', details: err.message }));
        });

        socket.on('timeout', () => {
            socket.destroy();
            resolve(NextResponse.json({ status: 'secure', message: 'Timeout' }));
        });

        socket.connect(21, hostname);
    });
}

async function probeHeaders(url: string) {
    try {
        const response = await fetch(url, { method: 'HEAD', redirect: 'follow' });
        const headers = response.headers;
        
        const missing = [];
        if (!headers.has('content-security-policy')) missing.push('Content-Security-Policy');
        if (!headers.has('x-frame-options')) missing.push('X-Frame-Options');
        
        if (missing.length > 0) {
            return NextResponse.json({
                status: 'vulnerable',
                message: 'Missing Critical Headers',
                details: `Missing: ${missing.join(', ')}`,
                impact: `The absence of ${missing[0]} allows attackers to perform ${missing[0].includes('CSP') ? 'Cross-Site Scripting (XSS)' : 'Clickjacking'} attacks.`
            });
        }
        return NextResponse.json({ status: 'secure', message: 'Headers Present' });
    } catch (e: any) {
        return NextResponse.json({ error: e.message }, { status: 500 });
    }
}

async function probeDMARC(hostname: string) {
    try {
        const dns = require('dns').promises;
        const dmarcRecords = await dns.resolveTxt(`_dmarc.${hostname}`).catch(() => []);
        const hasDmarc = dmarcRecords.some((record: string[]) => record.join('').includes('v=DMARC1'));

        if (!hasDmarc) {
            return NextResponse.json({
                status: 'vulnerable',
                message: 'Email Spoofing Possible',
                details: 'No DMARC record found for this domain.',
                impact: 'Attackers can send fraudulent emails from your domain name to trick your customers or steal credentials.'
            });
        }
        return NextResponse.json({ status: 'secure', message: 'DMARC Configured' });
    } catch (e: any) {
        return NextResponse.json({ error: e.message }, { status: 500 });
    }
}
