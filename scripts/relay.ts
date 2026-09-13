// No HTTP parsing or general proxying here. This isolated sidecar has one Unix
// socket directory mount and no external network. The host gateway validates all
// model requests; the optional proxy socket exists only when the host enabled it.
import { createServer, createConnection } from 'node:net';
function relay(port: number, socketPath: string): void {
  const server = createServer(client => {
    const host = createConnection(socketPath);
    client.on('error', () => host.destroy());
    host.on('error', () => client.destroy());
    client.on('close', () => host.destroy());
    host.on('close', () => client.destroy());
    client.pipe(host).pipe(client);
  });
  server.maxConnections = 16;
  server.on('error', () => process.exit(1));
  server.listen(port, '127.0.0.1', () => process.stdout.write(`ready ${port}\n`));
  process.on('SIGTERM', () => { server.close(); process.exit(); });
}
relay(17840, '/run/sealgate/gateway.sock');
relay(17841, '/run/sealgate/proxy.sock');
