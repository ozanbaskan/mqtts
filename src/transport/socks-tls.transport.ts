import { Transport } from './transport';
import { TlsTransportOptions } from './tls.transport';
import { SocksClient, SocksProxy } from 'socks';
import { connect } from 'tls';
import { Duplex } from 'stream';
import { IllegalStateError } from '../errors';

export interface SocksTlsTransportOptions extends TlsTransportOptions {
    proxyOptions: SocksProxy;
}

export class SocksTlsTransport extends Transport<SocksTlsTransportOptions> {
    public duplex?: Duplex;

    constructor(options: SocksTlsTransportOptions) {
        super(options);
        this.reset();
    }

    reset() {
        if (this.duplex && !this.duplex.destroyed) this.duplex.destroy();

        this.duplex = undefined;
    }

    async connect(): Promise<void> {
        if (this.duplex) throw new IllegalStateError('Still connected.');

        const info = await SocksClient.createConnection({
            proxy: this.options.proxyOptions,
            destination: {
                host: this.options.host,
                port: this.options.port,
            },
            command: 'connect',
        });

        return new Promise((resolve, reject) => {
            const tlsSocket = connect({
                ...this.options.additionalOptions,
                socket: info.socket,
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
