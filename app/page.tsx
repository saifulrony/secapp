import Scanner from '@/components/Scanner';

export default function Home() {
    return (
        <main>
            <h1>Aegis Scanner</h1>
            <p className="subtitle">
                An advanced, real-time vulnerability detection engine. Instantly analyze security headers and identify exposed configuration files with premium visualization.
            </p>

            <Scanner />
        </main>
    );
}
