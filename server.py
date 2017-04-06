#!/usr/bin/env python

from binascii import hexlify
import base64
import grp
import json
import os
import paramiko
import pwd
import socket
import sys
import threading
import time
import traceback

os.chdir(os.path.dirname(os.path.realpath(__file__)))
raw_config = open('data/config.json').read()
config = json.loads(raw_config)
host_key = paramiko.RSAKey(filename=config['key'])

# Set up logging
paramiko.util.log_to_file('data/error_log')
log_pipe = None
if (config['log'] is not False):
    log_pipe = open(config['log'], "a")


def log_event(addr, username, password):
    if (log_pipe is not None):
        try:
            log_pipe.write('\t'.join([time.strftime('%b-%d-%Y %H:%M:%S'), addr, username, password]) + '\n')
            log_pipe.flush()
        except Exception as e:
            raise e


class Server(paramiko.ServerInterface):
    def __init__(self, addr):
        self.addr = addr;
        self.event = threading.Event()
        self.has_authenticated_before = False

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_interactive(self, username, submethods):
        if self.has_authenticated_before:
            return paramiko.AUTH_FAILED
        else:
            self.has_authenticated_before = True
            return paramiko.InteractiveQuery('', config['banner'])

    def check_auth_password(self, username, password):
        log_event(addr[0], username, password)
        time.sleep(3)
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        time.sleep(1)
        return paramiko.AUTH_FAILED

    def check_auth_interactive_response(self, responses):
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'keyboard-interactive,publickey,password'

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth,
                                  pixelheight, modes):
        return True


def incoming_connection(client, addr):
    try:
        t = paramiko.Transport(client)
        t.local_version = 'SSH-2.0-OpenSSH_4.3'

        # Try to load server moduli for gex
        try:
            t.load_server_moduli()
        except:
            print('Failed to load moduli -- gex will be unsupported.')
            raise

        # Start the server & negotiate with the client
        server = Server(addr)
        t.add_server_key(host_key)
        try:
            t.start_server(server=server)
        except paramiko.SSHException as x:
            print('SSH negotiation failed.')
            try:
                t.close()
            except Exception as e:
                raise e
            return

        # Wait for auth
        t.accept(60)
        try:
            t.close()
        except Exception as e:
            raise e
        return

    except Exception as e:
        print('Caught exception: ' + str(e.__class__) + ': ' + str(e))
        traceback.print_exc()
        try:
            t.close()
        except Exception as e:
            raise e
        return

# Bind to the port
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', config['port']))
except Exception as e:
    print('Could not bind to port: ' + str(e))
    traceback.print_exc()

# Drop privileges
if os.getuid() == 0:
    try:
        os.setgroups([])
        os.setgid(grp.getgrnam('nogroup').gr_gid)
        os.setuid(pwd.getpwnam('nobody').pw_uid)
    except:
        print("CAUTION: could not drop root!")

# Start listening for connections
server_listening = True
while server_listening:
    try:
        sock.listen(100)
        print('Start.')
        client, addr = sock.accept()

        threading.Thread(target=incoming_connection, args=[client, addr]).start()
    except Exception as e:
        print("Couldn't wait for connection: " + str(e))
        traceback.print_exc()

sock.close()
if (log_pipe is not None):
    log_pipe.close()
