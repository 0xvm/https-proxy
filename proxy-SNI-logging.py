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

def relay_https_traffic(ssl_client_socket, hostname, port, address, cert_file, key_file, debug):
    """Relays encrypted traffic between the client and the destination server."""
    try:
        # Create a socket to the destination server
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Wrap the server socket with SSL
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # The following settings DISABLE CERTIFICATE VERIFICATION, making the
            # proxy vulnerable to MITM attacks. This is ONLY acceptable for
            # very specific, controlled use cases where security is not a concern.
            context.check_hostname = False  # Disable hostname checking
            context.verify_mode = ssl.CERT_NONE  # Disable certificate verification
            ssl_server_socket = context.wrap_socket(server_socket, server_hostname=hostname)  # SNI!
        except Exception as e:
            logging.error(f"Error wrapping server socket with SSL: {e}")
            return
        try:
            ssl_server_socket.connect((hostname, port))
        except Exception as e:
            logging.error(f"Error connecting to {hostname}:{port}: {e}")
            return  # Exit if cannot connect
        # Relay data between the client and the server
        sockets = [ssl_client_socket, ssl_server_socket]  # Using SSL wrapped sockets.
        while True:
            readable, _, _ = select.select(sockets, [], [])
            for sock in readable:
                if sock is ssl_client_socket:
                    try:
                        data = ssl_client_socket.recv(262144)
                    except ssl.SSLError as e:
                        logging.warning(f"SSL Error receiving from client: {e}")
                        data = None  # Break the loop if there's an SSL error
                    if not data:
                        logging.info(f"Client {address} disconnected.")
                        return
                    if debug:
                        try:
                            request_str = data.decode('utf-8', errors='ignore')
                            logging.info(f"Full HTTPS Request from Client to Server:n{request_str}")
                        except:
                            logging.info("Could not decode HTTPS Request from Client to Server for debugging")

                    if data:
                        try:
                            request_str = data.decode('utf-8', errors='ignore')
                            request_time = datetime.datetime.now()
                            log_traffic(hostname, request=request_str, request_time=request_time) # Log HTTPS request

                        except:
                            logging.info("Could not decode HTTPS Request from Client to Server for logging")
                    logging.debug(f"Received {len(data)} bytes from client {address} for {hostname}:{port}")
                    ssl_server_socket.sendall(data)  # Send encrypted data to the server
                else:
                    try:
                        data = ssl_server_socket.recv(262144)
                    except ConnectionResetError:
                        logging.warning(f"Server {hostname}:{port} disconnected.")
                        return
                    if not data:
                        logging.info(f"Server {hostname}:{port} disconnected.")
                        return
                    if debug:
                        try:
                            response_str = data.decode('utf-8', errors='ignore')
                            logging.info(f"Full HTTPS Response from Server to Client:n{response_str}")
                        except:
                            logging.info("Could not decode HTTPS Response from Server to Client for debugging")

                    if data:
                        try:
                            response_str = data.decode('utf-8', errors='ignore')
                            response_time = datetime.datetime.now()
                            log_traffic(hostname, response=response_str, response_time=response_time) # Log HTTPS response

                        except:
                            logging.info("Could not decode HTTPS Response from Server to Client for logging")
                    logging.debug(f"Received {len(data)} bytes from server {hostname}:{port} for client {address}")
                    try:
                        ssl_client_socket.sendall(data)  # Send encrypted data to the client
                    except ssl.SSLError as e:
                        logging.warning(f"SSL Error sending to client: {e}")
                        return  # Stop relaying if we can't send due to SSL errors
    except Exception as e:
        logging.error(f"Error relaying HTTPS traffic for {hostname}:{port}: {e}")
    finally:
        try:
            ssl_server_socket.close()
            ssl_client_socket.close()  # Close the SSL wrapped socket.
        except Exception:
            pass  # Socket may already be closed.

def handle_client(client_socket, address, cert_file, key_file, debug):
    """Handles a single client connection."""
    try:
        request = client_socket.recv(262144)
        if not request:
            logging.warning(f"Empty request from {address}. Closing connection.")
            return

        request_str = request.decode('utf-8', errors='ignore')  # Decode the request
        logging.debug(f"Received request from {address}:\n{request_str}")

        # Determine if it's an HTTP CONNECT (for HTTPS) or a regular HTTP request
        if request_str.startswith('CONNECT'):
            # Handle HTTPS CONNECT request (Man-in-the-Middle)
            handle_https_connect(client_socket, request_str, address, cert_file, key_file, debug)
        else:
            # Handle regular HTTP request
            handle_http_request(client_socket, request, debug)

    except ConnectionResetError:
        logging.warning(f"Connection reset by peer: {address}")
    except Exception as e:
        logging.error(f"Error handling client {address}: {e}")
    finally:
        try:
            client_socket.close()
        except Exception:
            pass  # Socket may already be closed.

def handle_http_request(client_socket, request, debug):
    """Handles a regular HTTP request."""
    try:
        # Parse the request (basic example)
        request_str = request.decode('utf-8', errors='ignore')
        first_line = request_str.split('n')[0]
        method, path, _ = first_line.split(' ') if len(first_line.split(' ')) == 3 else (None, None, None)
        if not method or not path:
            logging.warning(f"Invalid HTTP request: {first_line}")
            return
        # Forward the request to the destination server
        try:
            # Extract hostname and port. Handles both relative and absolute URLs.
            if path.startswith('http'):
                hostname = path.split('/')[2]
            else:
                # For relative paths, extract from the 'Host' header
                host_header = next((line for line in request_str.split('n') if line.startswith('Host:')), None)
                if host_header:
                    hostname = host_header.split(': ')[1].strip()  # Extract hostname
                else:
                    logging.warning("Host header not found in request.")
                    return  # Can't proceed without a host.
                if not hostname:
                    logging.warning("Hostname is empty")
                    return
            port = 80  # Default HTTP port
            if ':' in hostname:
                hostname, port_str = hostname.split(':')
                port = int(port_str)
            logging.info(f"Forwarding HTTP request to {hostname}:{port}")

            # Log the request
            request_time = datetime.datetime.now()
            log_traffic(hostname, request=request_str, request_time=request_time)  # Log request

            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((hostname, port))
            server_socket.sendall(request)  # Send the original request
            if debug:
                logging.info(f"Full HTTP Request:n{request_str}")
            # Relay the response back to the client
            response_parts = []
            while True:
                response = server_socket.recv(262144)
                if not response:
                    break
                client_socket.sendall(response)
                response_parts.append(response)
            if debug:
                response_str = b''.join(response_parts).decode('utf-8', errors='ignore')
                logging.info(f"Full HTTP Response:n{response_str}")

            # Log the response
            response_time = datetime.datetime.now()
            response_str = b''.join(response_parts).decode('utf-8', errors='ignore')
            log_traffic(hostname, response=response_str, response_time=response_time)  # Log response

            server_socket.close()
        except Exception as e:
            logging.error(f"Error forwarding HTTP request: {e}")
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

