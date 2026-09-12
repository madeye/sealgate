// No HTTP parsing or general proxying here. This isolated sidecar has one Unix
// socket mount and no external network. The host gateway validates all requests.
import { createServer, createConnection } from 'node:net';
const server = createServer(client => {
  const host = createConnection('/run/hecc/gateway.sock');
  client.on('error', () => host.destroy());
  host.on('error', () => client.destroy());
  client.on('close', () => host.destroy());
  host.on('close', () => client.destroy());
  client.pipe(host).pipe(client);
});
server.maxConnections = 16;
server.on('error', () => process.exit(1));
server.listen(17840, '127.0.0.1', () => process.stdout.write('ready\n'));
process.on('SIGTERM', () => { server.close(); process.exit(); });
