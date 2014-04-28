import base64
from hashlib import sha256
from threading import Lock

from construct import *

from base_plugin import BasePlugin
from packets import handshake_response, handshake_challenge, connect_response, client_connect
from utility_functions import build_packet
from packets.packet_types import Packets


def generate_handshake_response(challenge, account, password, rounds=5000):
    """
    Calculate the response for a handshake, see
    http://starbound-dev.org/networking/connecting.html
    """
    salt = account + challenge
    hash = sha256(password).digest()
    for i in range(rounds):
        hash = sha256(hash + salt).digest()
    return base64.b64encode(hash)

# TODO: Fetch these from a database
valid_logins = [
    ('user123', 'password123'),
]


class DBAuthPlugin(BasePlugin):
    """
    Authorize users against a database instead of the passwort list in starbound.config.
    """

    # This plugin has still some very ugly hacks that make it work, so be careful when you use it
    name = "db_auth_plugin"

    lock = Lock()

    def activate(self):
        super(DBAuthPlugin, self).activate()
        self.expected = {}
        self.challenge = {}
        # TODO: Fetch from config.json
        self.real_pw = ''

    def on_handshake_challenge(self, data):
        parsed = handshake_challenge().parse(data.data)
        # Note: The program generates ALL possible hashes here. You probably do not want
        # to use it in this form if you have more than 50 users on your server.
        # TODO: Implement some form of guessing.
        expected = [generate_handshake_response(parsed.salt, user, pw, parsed.round_count) for
                    user, pw in valid_logins]
        ip = self.protocol.transport.getPeer().host
        with self.lock:
            self.expected[ip] = expected
            self.challenge[ip] = parsed.salt
        new_data = build_packet(Packets.HANDSHAKE_CHALLENGE,
            handshake_challenge().build(parsed)
        )
        self.protocol.transport.write(new_data)
        return False

    def on_handshake_response(self, data):
        ip = self.protocol.transport.getPeer().host
        parsed = handshake_response().parse(data.data)
        with self.lock:
            expected = self.expected.pop(ip, [])
            challenge = self.challenge.pop(ip, '')
        if parsed.hash in expected:
            # found a match
            # fake an actual authentication with the server here
            new_hash = generate_handshake_response(challenge, '', self.real_pw, 5000)
            new_data = build_packet(Packets.HANDSHAKE_RESPONSE, handshake_response().build(
                Container(hash=new_hash, claim_response='')))
            self.protocol.client_protocol.transport.write(new_data)
            return False
        else:
            # found no match. Send the user home.
            self.reject_with_reason('Wrong account name or password.')
            return False

    def on_client_connect(self, data):
        parsed = client_connect().parse(data.data)
        # strip the account from the connect package
        parsed.account = ''
        new_data = build_packet(Packets.CLIENT_CONNECT, client_connect().build(parsed))
        self.protocol.client_protocol.transport.write(new_data)
        return False

    def reject_with_reason(self, reason):
        magic_sector = "AQAAAAwAAAAy+gofAAX14QD/Z2mAAJiWgAUFYWxwaGEMQWxwaGEgU2VjdG9yAAAAELIfhbMFQWxwaGEHAgt0aHJlYXRMZXZlbAYCBAIEAg51bmxvY2tlZEJpb21lcwYHBQRhcmlkBQZkZXNlcnQFBmZvcmVzdAUEc25vdwUEbW9vbgUGYmFycmVuBQ1hc3Rlcm9pZGZpZWxkBwcCaWQFBWFscGhhBG5hbWUFDEFscGhhIFNlY3RvcgpzZWN0b3JTZWVkBISWofyWZgxzZWN0b3JTeW1ib2wFFy9jZWxlc3RpYWwvc2VjdG9yLzEucG5nCGh1ZVNoaWZ0BDsGcHJlZml4BQVBbHBoYQ93b3JsZFBhcmFtZXRlcnMHAgt0aHJlYXRMZXZlbAYCBAIEAg51bmxvY2tlZEJpb21lcwYHBQRhcmlkBQZkZXNlcnQFBmZvcmVzdAUEc25vdwUEbW9vbgUGYmFycmVuBQ1hc3Rlcm9pZGZpZWxkBGJldGELQmV0YSBTZWN0b3IAAADUWh1fvwRCZXRhBwILdGhyZWF0TGV2ZWwGAgQEBAQOdW5sb2NrZWRCaW9tZXMGCQUEYXJpZAUGZGVzZXJ0BQhzYXZhbm5haAUGZm9yZXN0BQRzbm93BQRtb29uBQZqdW5nbGUFBmJhcnJlbgUNYXN0ZXJvaWRmaWVsZAcHAmlkBQRiZXRhBG5hbWUFC0JldGEgU2VjdG9yCnNlY3RvclNlZWQEtYuh6v5+DHNlY3RvclN5bWJvbAUXL2NlbGVzdGlhbC9zZWN0b3IvMi5wbmcIaHVlU2hpZnQEAAZwcmVmaXgFBEJldGEPd29ybGRQYXJhbWV0ZXJzBwILdGhyZWF0TGV2ZWwGAgQEBAQOdW5sb2NrZWRCaW9tZXMGCQUEYXJpZAUGZGVzZXJ0BQhzYXZhbm5haAUGZm9yZXN0BQRzbm93BQRtb29uBQZqdW5nbGUFBmJhcnJlbgUNYXN0ZXJvaWRmaWVsZAVnYW1tYQxHYW1tYSBTZWN0b3IAAADMTMw79wVHYW1tYQcCC3RocmVhdExldmVsBgIEBgQGDnVubG9ja2VkQmlvbWVzBgoFBGFyaWQFBmRlc2VydAUIc2F2YW5uYWgFBmZvcmVzdAUEc25vdwUEbW9vbgUGanVuZ2xlBQpncmFzc2xhbmRzBQZiYXJyZW4FDWFzdGVyb2lkZmllbGQHBwJpZAUFZ2FtbWEEbmFtZQUMR2FtbWEgU2VjdG9yCnNlY3RvclNlZWQEs4nM4e9uDHNlY3RvclN5bWJvbAUXL2NlbGVzdGlhbC9zZWN0b3IvMy5wbmcIaHVlU2hpZnQEPAZwcmVmaXgFBUdhbW1hD3dvcmxkUGFyYW1ldGVycwcCC3RocmVhdExldmVsBgIEBgQGDnVubG9ja2VkQmlvbWVzBgoFBGFyaWQFBmRlc2VydAUIc2F2YW5uYWgFBmZvcmVzdAUEc25vdwUEbW9vbgUGanVuZ2xlBQpncmFzc2xhbmRzBQZiYXJyZW4FDWFzdGVyb2lkZmllbGQFZGVsdGEMRGVsdGEgU2VjdG9yAAAA1Ooj2GcFRGVsdGEHAgt0aHJlYXRMZXZlbAYCBAgECA51bmxvY2tlZEJpb21lcwYOBQRhcmlkBQZkZXNlcnQFCHNhdmFubmFoBQZmb3Jlc3QFBHNub3cFBG1vb24FBmp1bmdsZQUKZ3Jhc3NsYW5kcwUFbWFnbWEFCXRlbnRhY2xlcwUGdHVuZHJhBQh2b2xjYW5pYwUGYmFycmVuBQ1hc3Rlcm9pZGZpZWxkBwcCaWQFBWRlbHRhBG5hbWUFDERlbHRhIFNlY3RvcgpzZWN0b3JTZWVkBLWdop7hTgxzZWN0b3JTeW1ib2wFFy9jZWxlc3RpYWwvc2VjdG9yLzQucG5nCGh1ZVNoaWZ0BHgGcHJlZml4BQVEZWx0YQ93b3JsZFBhcmFtZXRlcnMHAgt0aHJlYXRMZXZlbAYCBAgECA51bmxvY2tlZEJpb21lcwYOBQRhcmlkBQZkZXNlcnQFCHNhdmFubmFoBQZmb3Jlc3QFBHNub3cFBG1vb24FBmp1bmdsZQUKZ3Jhc3NsYW5kcwUFbWFnbWEFCXRlbnRhY2xlcwUGdHVuZHJhBQh2b2xjYW5pYwUGYmFycmVuBQ1hc3Rlcm9pZGZpZWxkB3NlY3RvcngIWCBTZWN0b3IAAABjhzJHNwFYBwILdGhyZWF0TGV2ZWwGAgQKBBQOdW5sb2NrZWRCaW9tZXMGDgUEYXJpZAUGZGVzZXJ0BQhzYXZhbm5haAUGZm9yZXN0BQRzbm93BQRtb29uBQZqdW5nbGUFCmdyYXNzbGFuZHMFBW1hZ21hBQl0ZW50YWNsZXMFBnR1bmRyYQUIdm9sY2FuaWMFBmJhcnJlbgUNYXN0ZXJvaWRmaWVsZAcIAmlkBQdzZWN0b3J4BG5hbWUFCFggU2VjdG9yCnNlY3RvclNlZWQEmPDzkpxuDHNlY3RvclN5bWJvbAUXL2NlbGVzdGlhbC9zZWN0b3IveC5wbmcIaHVlU2hpZnQEgTQIcHZwRm9yY2UDAQZwcmVmaXgFAVgPd29ybGRQYXJhbWV0ZXJzBwILdGhyZWF0TGV2ZWwGAgQKBBQOdW5sb2NrZWRCaW9tZXMGDgUEYXJpZAUGZGVzZXJ0BQhzYXZhbm5haAUGZm9yZXN0BQRzbm93BQRtb29uBQZqdW5nbGUFCmdyYXNzbGFuZHMFBW1hZ21hBQl0ZW50YWNsZXMFBnR1bmRyYQUIdm9sY2FuaWMFBmJhcnJlbgUNYXN0ZXJvaWRmaWVsZA=="
        unlocked_sector_magic = base64.decodestring(magic_sector.encode("ascii"))
        rejection = build_packet(Packets.CONNECT_RESPONSE, connect_response().build(
            Container(success=False, client_id=0, reject_reason=reason)) + unlocked_sector_magic)
        self.protocol.transport.write(rejection)
        self.protocol.transport.loseConnection()