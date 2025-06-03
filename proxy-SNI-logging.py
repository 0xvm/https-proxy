#python proxy-SNI-logging.py --cert ca.crt --key ca.key
import socket
import ssl
import threading
import select
import logging
import os
import argparse
import subprocess  # For openssl calls
import tempfile # for CSR
import datetime
from urllib.parse import urlparse


# Configuration
DEFAULT_PORT = 8080
CERT_FILE = 'ca.crt'  # Path to the CA certificate (used for signing)
KEY_FILE = 'ca.key'  # Path to the CA key (used for signing)
# Create a directory for storing generated certificates
CERT_DIR = "certs"
if not os.path.exists(CERT_DIR):
    os.makedirs(CERT_DIR)


def log_traffic(domain, request=None, response=None, request_time=None, response_time=None):
    """Logs HTTP/HTTPS requests and responses for a given domain."""
    log_dir = "traffic_logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    log_file = os.path.join(log_dir, f"{domain}.log")

    try:
        with open(log_file, "a", encoding="utf-8") as f:
            if request:
                timestamp = request_time.strftime("%Y-%m-%d %H:%M:%S.%f") if request_time else datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
                f.write(f"[{timestamp}] REQUEST:\n{request}\n\n")
            if response:
                timestamp = response_time.strftime("%Y-%m-%d %H:%M:%S.%f") if response_time else datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
                f.write(f"[{timestamp}] RESPONSE:\n{response}\n\n")
    except Exception as e:
        logging.error(f"Error logging traffic for {domain}: {e}")

# Logging (as before)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Certificate Cache
certificate_cache = {}

def generate_self_signed_cert(cert_file, key_file):  # As before
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        logging.info("Generating self-signed certificate...")
        try:
            import subprocess
            subprocess.run([
                'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                '-keyout', key_file, '-out', cert_file,
                '-days', '365', '-nodes',
                '-subj', '/CN=localhost'  # Common Name, adjust as needed
            ], check=True, capture_output=True, text=True)
            logging.info("Self-signed certificate generated successfully.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error generating certificate: {e.stderr}")
            exit(1)
    else:
        logging.info("Certificate and key files already exist. Skipping generation.")

def get_certificate(hostname, ca_cert, ca_key):
    """Retrieves or generates a certificate for the given hostname."""
    cert_path = os.path.join(CERT_DIR, f"{hostname}.crt")
    key_path = os.path.join(CERT_DIR, f"{hostname}.key")
    cnf_path = os.path.join(CERT_DIR, f"{hostname}.cnf")  # Path to the domain-specific CNF

    if hostname in certificate_cache:  # Check the cache
        logging.debug(f"Using cached certificate for {hostname}")
        return certificate_cache[hostname]

    if os.path.exists(cert_path) and os.path.exists(key_path) and os.path.exists(cnf_path):  # Check existing files
        logging.info(f"Loading existing certificate for {hostname} from disk")
        try:
            with open(cert_path, 'r') as crt_file, open(key_path, 'r') as key_file:
                cert = crt_file.read()
                key = key_file.read()
            certificate_cache[hostname] = (cert, key)  # Add to cache
            return cert, key  # Return key/cert instead of loading again
        except Exception as e:
            logging.error(f"Failed to load cert/key {e}")
            return None, None # prevent crash if loading fails

    # Generate a new certificate if not found
    logging.info(f"Generating new certificate for {hostname}")
    try:
        # 1. Generate private key for the server
        server_key_path = os.path.join(CERT_DIR, f"{hostname}.key")
        subprocess.run(['openssl', 'genrsa', '-out', server_key_path, '2048'], check=True, capture_output=True, text=True)

        # 2. Create a domain-specific openssl.cnf file
        with open(cnf_path, 'w') as f:
            f.write(f'''[req]
distinguished_name = req_distinguished_name

[req_distinguished_name]

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = {hostname}
''')

        # 3. Create a CSR
        with tempfile.NamedTemporaryFile(delete=True, suffix=".csr") as csr_temp:  # create temp file for csr
            server_csr_path = csr_temp.name  # get path for temp file to be used in subprocess
            subj = f"/CN={hostname}"
            cmd = ['openssl', 'req', '-new', '-key', server_key_path, '-out', server_csr_path, '-subj', subj, '-config', cnf_path] # Added config
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            logging.debug(f"CSR command: {' '.join(cmd)}, output: {result.stdout}, errors: {result.stderr}")

            # 4. Sign the CSR with the CA
            server_cert_path = os.path.join(CERT_DIR, f"{hostname}.crt")
            cmd = ['openssl', 'x509', '-req', '-in', server_csr_path, '-CA', ca_cert, '-CAkey', ca_key,
                   '-CAcreateserial', '-out', server_cert_path, '-days', '365',
                   '-extfile', cnf_path,  # Use the extensions file
                   '-extensions', 'v3_req']
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            logging.debug(f"Sign CSR command: {' '.join(cmd)}, output: {result.stdout}, errors: {result.stderr}")

            with open(server_cert_path, 'r') as crt_file, open(server_key_path, 'r') as key_file:
                cert = crt_file.read()
                key = key_file.read()

            certificate_cache[hostname] = (cert, key)
            return cert, key

    except subprocess.CalledProcessError as e:
        logging.error(f"Error generating certificate for {hostname}: {e.stderr}")
        return None, None


def handle_https_connect(client_socket, request_str, address, cert_file, key_file, debug):
    """Handles an HTTPS CONNECT request (Man-in-the-Middle)."""
    try:
        # Extract the hostname and port from the CONNECT request
        first_line = request_str.split('\n')[0]
        _, host, _ = first_line.split(' ')
        hostname, port = host.split(':') if ':' in host else (host, 443)
        port = int(port)

        logging.info(f"Received HTTPS CONNECT to {hostname}:{port} from {address}")
        if debug:
            logging.info(f"Full HTTP CONNECT Request:\n{request_str}")

        # Send a 200 Connection Established response to the client
        client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        # Get or generate the certificate
        server_cert, server_key = get_certificate(hostname, cert_file, key_file)
        if not server_cert or not server_key:
            logging.error(f"Failed to get certificate for {hostname}")
            return

        # Wrap the client socket with SSL using the generated certificate
        try:
            cert_path = os.path.join(CERT_DIR, f"{hostname}.crt")
            key_path = os.path.join(CERT_DIR, f"{hostname}.key")
            logging.debug(f"Loading certificate from: {cert_path}, key from: {key_path}") # added logging!

            # Create a *new* SSLContext for each connection
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=cert_path, keyfile=key_path)  # Load the dynamically generated certificate

            # Wrap the client socket with SSL
            ssl_client_socket = context.wrap_socket(client_socket, server_side=True) # added logging!
        except Exception as e:
            logging.error(f"Error wrapping socket with SSL: {e}")
            logging.error(f"Certificate path: {os.path.join(CERT_DIR, f'{hostname}.crt')}")
            logging.error(f"Key path: {os.path.join(CERT_DIR, f'{hostname}.key')}") # added logging!
            return
        # Now, the client is communicating with us over SSL.  Relay traffic.
        relay_https_traffic(ssl_client_socket, hostname, port, address, cert_file, key_file, debug)

    except Exception as e:
        logging.error(f"Error handling HTTPS CONNECT: {e}")


def relay_https_traffic(ssl_client_socket, hostname, port, address, ca_cert, ca_key, debug):
    """
    MITM an HTTPS CONNECT tunnel by intercepting exactly one HTTP request,
    rewriting it to force Connection: close, sending it upstream, and
    then forwarding back the full response until EOF.
    """

    CRLF = '\r\n'

    # 1) Dial out to the real server over TLS (with SNI, no cert checks)
    plain_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context    = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode    = ssl.CERT_NONE
    ssl_server_socket     = context.wrap_socket(plain_sock, server_hostname=hostname)
    ssl_server_socket.connect((hostname, port))

    try:
        # 2) Read one full HTTP request (headers+body) from the client‐side TLS
        head, body = recv_full_request(ssl_client_socket)

        # 3) Split into lines and pull out the request‐line + any original Host:
        text_lines   = head.decode('iso-8859-1').split(CRLF)
        request_line = text_lines[0]
        method, path, version = request_line.split(' ', 2)

        orig_host_val = None
        filtered     = []
        for hdr in text_lines[1:]:
            if not hdr:
                continue
            name, _, val = hdr.partition(':')
            nl = name.strip().lower()
            # drop proxy-*, host, and connection headers
            if nl.startswith('proxy-'):
                continue
            if nl == 'host':
                orig_host_val = val.strip()
                continue
            if nl == 'connection':
                continue
            filtered.append(hdr)

        # 4) Rebuild the header block
        new_lines = [f"{method} {path} {version}"]
        new_lines += filtered

        # 5) Insert exactly one Host: header
        if orig_host_val:
            new_lines.append(f"Host: {orig_host_val}")
        else:
            # fallback to the CONNECT target
            hostport = hostname if port in (80, 443) else f"{hostname}:{port}"
            new_lines.append(f"Host: {hostport}")

        # 6) Force the upstream server to close
        new_lines.append("Connection: close")

        # 7) Reassemble with real CRLFs
        new_head    = CRLF.join(new_lines) + CRLF + CRLF
        new_request = new_head.encode('iso-8859-1') + body

        if debug:
            logging.debug(">> [HTTPS‐MITM] Rewritten upstream request:\n%s", new_head)

        # 8) Send the single request into the server‐side TLS
        ssl_server_socket.sendall(new_request)

        # 9) Relay the full response until the server closes (EOF)
        while True:
            chunk = ssl_server_socket.recv(524288)
            if not chunk:
                break
            ssl_client_socket.sendall(chunk)
            if debug:
                try:
                    logging.debug("<< [HTTPS‐MITM] chunk:\n%s",
                                  chunk.decode('utf-8', 'ignore'))
                except:
                    logging.debug("<< [HTTPS‐MITM] binary chunk %d bytes", len(chunk))

    except Exception as e:
        logging.error(f"Error in relay_https_traffic({hostname}:{port}): {e}")
    finally:
        try:
            ssl_server_socket.close()
        except:
            pass
        try:
            ssl_client_socket.close()
        except:
            pass





def handle_client(client_socket, address, cert_file, key_file, debug):
    """
    Top‐level per‐connection handler.  Grabs the first recv(),
    then dispatches to HTTP or HTTPS paths.
    """
    try:
        initial = client_socket.recv(524288)
        if not initial:
            return
        text = initial.decode('utf-8', 'ignore')
        if text.startswith('CONNECT'):
            # your existing HTTPS‐MITM handler
            handle_https_connect(client_socket, text, address, cert_file, key_file, debug)
        else:
            handle_http_request(client_socket, initial, debug)
    except Exception as e:
        logging.error(f"Error in handle_client({address}): {e}")
    finally:
        try:
            client_socket.close()
        except:
            pass


def recv_full_request(client_sock, initial_data=b''):
    """
    Read from client_sock until we have seen the end of headers (\r\n\r\n),
    then if there is a Content-Length header, read exactly that many bytes
    of body before returning. initial_data is any bytes you already pulled.
    Returns: (head_bytes, body_bytes)
    """
    data = initial_data
    # 1) read until headers end
    while b'\r\n\r\n' not in data:
        chunk = client_sock.recv(524288)
        if not chunk:
            break
        data += chunk

    # split once on the header/body boundary
    head, sep, rest = data.partition(b'\r\n\r\n')
    header_lines = head.decode('iso-8859-1').split('\r\n')

    # 2) find Content-Length
    content_length = 0
    for line in header_lines:
        if line.lower().startswith('content-length:'):
            try:
                content_length = int(line.split(':', 1)[1].strip())
            except ValueError:
                content_length = 0
            break

    # 3) read the remainder of the body (if any)
    body = rest
    to_read = content_length - len(body)
    while to_read > 0:
        chunk = client_sock.recv(min(524288, to_read))
        if not chunk:
            break
        body += chunk
        to_read -= len(chunk)

    return head, body


def handle_http_request(client_socket, initial_buffer, debug=False):
    """
    Reads full HTTP request (headers+body), rewrites the request‐line to a
    relative path + Host:, forwards it to the origin, relays the response
    back, and in debug mode logs the full response.
    """
    try:
        # A) Read full headers+body, seeding with the bytes you already have
        head_bytes, body = recv_full_request(client_socket, initial_buffer)

        # B) Split into text lines to rewrite the request‐line + headers
        head_str = head_bytes.decode('iso-8859-1')
        lines = head_str.split('\r\n')
        if not lines or ' ' not in lines[0]:
            logging.warning("Invalid HTTP request-line, dropping")
            return

        method, full_url, version = lines[0].split(' ', 2)
        parsed = urlparse(full_url)

        # build the relative path
        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query

        # C) Rebuild the headers
        new_lines = [f"{method} {path} {version}"]
        saw_host = False
        for hdr in lines[1:]:
            if not hdr:
                continue
            name, _, val = hdr.partition(':')
            nl = name.strip().lower()
            # strip proxy-* headers
            if nl.startswith('proxy-'):
                continue
            # rewrite Host
            if nl == 'host':
                new_lines.append(f"Host: {parsed.netloc}")
                saw_host = True
            else:
                new_lines.append(hdr)
        if not saw_host:
            new_lines.append(f"Host: {parsed.netloc}")

        # D) Re-assemble the request
        new_head = '\r\n'.join(new_lines) + '\r\n\r\n'
        new_request = new_head.encode('iso-8859-1') + body

        if debug:
            logging.debug(">> Rewritten Request HEADERS:\n%s", new_head)
            if body:
                logging.debug(">> Rewritten Request BODY (%d bytes): %r",
                              len(body),
                              body[:100] + (b'...' if len(body) > 100 else b''))

        # E) Open a TCP connection to the real server
        host, sep, port = parsed.netloc.partition(':')
        port = int(port) if sep else 80
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect((host, port))

        # F) Send the full request
        server.sendall(new_request)

        # G) Relay + capture the response
        response_chunks = []
        while True:
            chunk = server.recv(524288)
            if not chunk:
                break
            client_socket.sendall(chunk)
            response_chunks.append(chunk)

            # per‐chunk debug (optional)
            if debug:
                try:
                    logging.debug("<< Response chunk:\n%s",
                                  chunk.decode('utf-8', 'ignore'))
                except:
                    logging.debug("<< Binary response chunk: %d bytes", len(chunk))

        # H) In debug, dump the full response once
        if debug and response_chunks:
            full_resp = b''.join(response_chunks).decode('utf-8', 'ignore')
            logging.debug("<< Full HTTP response:\n%s", full_resp)

        server.close()

    except Exception as e:
        logging.error(f"Error handling HTTP request: {e}")






def main():
    parser = argparse.ArgumentParser(description='Simple HTTP/HTTPS Forwarding Proxy')
    parser.add_argument('-p', '--port', type=int, default=DEFAULT_PORT, help=f'Port to listen on (default: {DEFAULT_PORT})')
    parser.add_argument('--cert', type=str, default=CERT_FILE, help=f'Path to the CA certificate file (default: {CERT_FILE})')
    parser.add_argument('--key', type=str, default=KEY_FILE, help=f'Path to the CA key file (default: {KEY_FILE})')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Ensure certificate and key files exist (or generate them)
    generate_self_signed_cert(args.cert, args.key)

    # Start the proxy server
    start_proxy_server(args.port, args.cert, args.key, args.debug)


def start_proxy_server(port, cert_file, key_file, debug):
    """Starts the proxy server."""
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow address reuse
        server_socket.bind(('0.0.0.0', port))  # Listen on all interfaces
        server_socket.listen(5)

        logging.info(f"Proxy server listening on port {port}")

        while True:
            client_socket, address = server_socket.accept()
            logging.info(f"Accepted connection from {address[0]}:{address[1]}")
            client_thread = threading.Thread(target=handle_client, args=(client_socket, address, cert_file, key_file, debug))
            client_thread.daemon = True  # Daemon threads exit when the main program does.
            client_thread.start()

    except OSError as e:
        logging.error(f"Error creating socket: {e}")
        if e.errno == 98:  # Address already in use
            logging.error(
                f"Port {port} is already in use.  Please specify a different port or close the application using this port.")
        exit(1)  # Exit if we cannot start the server
    except KeyboardInterrupt:
        logging.info("Shutting down the proxy server...")
    finally:
        try:
            server_socket.close()
        except:
            pass  # just ensure it's closed.
        logging.info("Proxy server stopped.")

if __name__ == "__main__":
    # Create an openssl.cnf file to be passed to openssl x509

    with open('openssl.cnf', 'w') as f:
        f.write('''[req]
distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
''')
    main()

