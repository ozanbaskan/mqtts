import { Transport } from './transport';
import { ConnectionOptions, connect, TLSSocket } from 'tls';
import { IllegalStateError } from '../errors';

export interface TlsTransportOptions {
    host: string;
    port: number;
    additionalOptions?: ConnectionOptions;
}
export class TlsTransport extends Transport<TlsTransportOptions> {
    public duplex?: TLSSocket;

    constructor(options: TlsTransportOptions) {
        super(options);
        this.reset();
    }

    reset() {
        if (this.duplex && !this.duplex.destroyed) this.duplex.destroy();

        this.duplex = undefined;
    }

    connect(): Promise<void> {
        if (this.duplex) throw new IllegalStateError('Still connected.');

        return new Promise((resolve, reject) => {
            const tlsSocket = connect({
                ...this.options.additionalOptions,
                host: this.options.host,
                port: this.options.port,
            });

            this.duplex = tlsSocket;

            const to = setTimeout(() => {
                tlsSocket.destroy();
                reject(new Error('OB TLS handshake timeout'));
            }, 10000);

            to.unref();
            tlsSocket.once('secureConnect', () => {
                clearTimeout(to);
                resolve();
            });

            tlsSocket.once('error', (err: Error) => {
                reject(err);
            });

            tlsSocket.once('end', () => {
                reject(new Error('TLS socket closed before handshake'));
            });
        });
    }
}
