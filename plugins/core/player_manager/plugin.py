import base64
import re

from construct import Container
from twisted.internet.task import LoopingCall
from twisted.words.ewords import AlreadyLoggedIn

from base_plugin import SimpleCommandPlugin
from manager import PlayerManager, Banned, Player, permissions, UserLevels
from packets import client_connect, connect_response
import packets
from utility_functions import build_packet, Planet


class PlayerManagerPlugin(SimpleCommandPlugin):
    name = "player_manager"
    commands = ["list_players", "delete_player"]

    def activate(self):
        super(PlayerManagerPlugin, self).activate()
        self.player_manager = PlayerManager(self.config)
        self.l_call = LoopingCall(self.check_logged_in)
        self.l_call.start(1, now=False)
        self.regexes = self.config.plugin_config['name_removal_regexes']

    def deactivate(self):
        del self.player_manager

    def check_logged_in(self):
        for player in self.player_manager.who():
            if player.protocol not in self.factory.protocols.keys():
                player.logged_in = False

    def on_client_connect(self, data):
        client_data = client_connect().parse(data.data)
        try:
            original_name = client_data.name
            for regex in self.regexes:
                client_data.name = re.sub(regex, "", client_data.name)
            if len(client_data.name.strip()) == 0:  # If the username is nothing but spaces.
                raise NameError("Your name must not be empty!")
            if client_data.name != original_name:
                self.logger.info("Player tried to log in with name %s, replaced with %s.",
                                 original_name, client_data.name)

            for duplicate_player in self.player_manager.all():
                if duplicate_player.name == client_data.name and duplicate_player.uuid != client_data.uuid:
                    self.logger.info("Got a duplicate player, asking player to change name")
                    raise NameError(
                        "The name of this character is already taken on the server! Please, create a new character with a different name or use Starcheat and change the name.")

            self.protocol.player = self.player_manager.fetch_or_create(
                name=client_data.name,
                uuid=str(client_data.uuid),
                ip=self.protocol.transport.getPeer().host,
                protocol=self.protocol.id,
            )

            return True
        except AlreadyLoggedIn:
            self.reject_with_reason(
                "You're already logged in! If this is not the case, please wait 10 seconds and try again.")
            self.logger.info("Already logged in user tried to log in.")
        except Banned:
            self.reject_with_reason("You have been banned!")
            self.logger.info("Banned user tried to log in.")
            return False
        except NameError as e:
            self.reject_with_reason(str(e))

    def reject_with_reason(self, reason):
        magic_sector = "AQAAAAwAAAAy+gofAAX14QD/Z2mAAJiWgAUFYWxwaGEMQWxwaGEgU2VjdG9yAAAAELIfhbMFQWxwaGEHAgt0aHJlYXRMZXZlbAYCBAIEAg51bmxvY2tlZEJpb21lcwYHBQRhcmlkBQZkZXNlcnQFBmZvcmVzdAUEc25vdwUEbW9vbgUGYmFycmVuBQ1hc3Rlcm9pZGZpZWxkBwcCaWQFBWFscGhhBG5hbWUFDEFscGhhIFNlY3RvcgpzZWN0b3JTZWVkBISWofyWZgxzZWN0b3JTeW1ib2wFFy9jZWxlc3RpYWwvc2VjdG9yLzEucG5nCGh1ZVNoaWZ0BDsGcHJlZml4BQVBbHBoYQ93b3JsZFBhcmFtZXRlcnMHAgt0aHJlYXRMZXZlbAYCBAIEAg51bmxvY2tlZEJpb21lcwYHBQRhcmlkBQZkZXNlcnQFBmZvcmVzdAUEc25vdwUEbW9vbgUGYmFycmVuBQ1hc3Rlcm9pZGZpZWxkBGJldGELQmV0YSBTZWN0b3IAAADUWh1fvwRCZXRhBwILdGhyZWF0TGV2ZWwGAgQEBAQOdW5sb2NrZWRCaW9tZXMGCQUEYXJpZAUGZGVzZXJ0BQhzYXZhbm5haAUGZm9yZXN0BQRzbm93BQRtb29uBQZqdW5nbGUFBmJhcnJlbgUNYXN0ZXJvaWRmaWVsZAcHAmlkBQRiZXRhBG5hbWUFC0JldGEgU2VjdG9yCnNlY3RvclNlZWQEtYuh6v5+DHNlY3RvclN5bWJvbAUXL2NlbGVzdGlhbC9zZWN0b3IvMi5wbmcIaHVlU2hpZnQEAAZwcmVmaXgFBEJldGEPd29ybGRQYXJhbWV0ZXJzBwILdGhyZWF0TGV2ZWwGAgQEBAQOdW5sb2NrZWRCaW9tZXMGCQUEYXJpZAUGZGVzZXJ0BQhzYXZhbm5haAUGZm9yZXN0BQRzbm93BQRtb29uBQZqdW5nbGUFBmJhcnJlbgUNYXN0ZXJvaWRmaWVsZAVnYW1tYQxHYW1tYSBTZWN0b3IAAADMTMw79wVHYW1tYQcCC3RocmVhdExldmVsBgIEBgQGDnVubG9ja2VkQmlvbWVzBgoFBGFyaWQFBmRlc2VydAUIc2F2YW5uYWgFBmZvcmVzdAUEc25vdwUEbW9vbgUGanVuZ2xlBQpncmFzc2xhbmRzBQZiYXJyZW4FDWFzdGVyb2lkZmllbGQHBwJpZAUFZ2FtbWEEbmFtZQUMR2FtbWEgU2VjdG9yCnNlY3RvclNlZWQEs4nM4e9uDHNlY3RvclN5bWJvbAUXL2NlbGVzdGlhbC9zZWN0b3IvMy5wbmcIaHVlU2hpZnQEPAZwcmVmaXgFBUdhbW1hD3dvcmxkUGFyYW1ldGVycwcCC3RocmVhdExldmVsBgIEBgQGDnVubG9ja2VkQmlvbWVzBgoFBGFyaWQFBmRlc2VydAUIc2F2YW5uYWgFBmZvcmVzdAUEc25vdwUEbW9vbgUGanVuZ2xlBQpncmFzc2xhbmRzBQZiYXJyZW4FDWFzdGVyb2lkZmllbGQFZGVsdGEMRGVsdGEgU2VjdG9yAAAA1Ooj2GcFRGVsdGEHAgt0aHJlYXRMZXZlbAYCBAgECA51bmxvY2tlZEJpb21lcwYOBQRhcmlkBQZkZXNlcnQFCHNhdmFubmFoBQZmb3Jlc3QFBHNub3cFBG1vb24FBmp1bmdsZQUKZ3Jhc3NsYW5kcwUFbWFnbWEFCXRlbnRhY2xlcwUGdHVuZHJhBQh2b2xjYW5pYwUGYmFycmVuBQ1hc3Rlcm9pZGZpZWxkBwcCaWQFBWRlbHRhBG5hbWUFDERlbHRhIFNlY3RvcgpzZWN0b3JTZWVkBLWdop7hTgxzZWN0b3JTeW1ib2wFFy9jZWxlc3RpYWwvc2VjdG9yLzQucG5nCGh1ZVNoaWZ0BHgGcHJlZml4BQVEZWx0YQ93b3JsZFBhcmFtZXRlcnMHAgt0aHJlYXRMZXZlbAYCBAgECA51bmxvY2tlZEJpb21lcwYOBQRhcmlkBQZkZXNlcnQFCHNhdmFubmFoBQZmb3Jlc3QFBHNub3cFBG1vb24FBmp1bmdsZQUKZ3Jhc3NsYW5kcwUFbWFnbWEFCXRlbnRhY2xlcwUGdHVuZHJhBQh2b2xjYW5pYwUGYmFycmVuBQ1hc3Rlcm9pZGZpZWxkB3NlY3RvcngIWCBTZWN0b3IAAABjhzJHNwFYBwILdGhyZWF0TGV2ZWwGAgQKBBQOdW5sb2NrZWRCaW9tZXMGDgUEYXJpZAUGZGVzZXJ0BQhzYXZhbm5haAUGZm9yZXN0BQRzbm93BQRtb29uBQZqdW5nbGUFCmdyYXNzbGFuZHMFBW1hZ21hBQl0ZW50YWNsZXMFBnR1bmRyYQUIdm9sY2FuaWMFBmJhcnJlbgUNYXN0ZXJvaWRmaWVsZAcIAmlkBQdzZWN0b3J4BG5hbWUFCFggU2VjdG9yCnNlY3RvclNlZWQEmPDzkpxuDHNlY3RvclN5bWJvbAUXL2NlbGVzdGlhbC9zZWN0b3IveC5wbmcIaHVlU2hpZnQEgTQIcHZwRm9yY2UDAQZwcmVmaXgFAVgPd29ybGRQYXJhbWV0ZXJzBwILdGhyZWF0TGV2ZWwGAgQKBBQOdW5sb2NrZWRCaW9tZXMGDgUEYXJpZAUGZGVzZXJ0BQhzYXZhbm5haAUGZm9yZXN0BQRzbm93BQRtb29uBQZqdW5nbGUFCmdyYXNzbGFuZHMFBW1hZ21hBQl0ZW50YWNsZXMFBnR1bmRyYQUIdm9sY2FuaWMFBmJhcnJlbgUNYXN0ZXJvaWRmaWVsZA=="
        unlocked_sector_magic = base64.decodestring(magic_sector.encode("ascii"))
        rejection = build_packet(
            packets.Packets.CONNECT_RESPONSE,
            packets.connect_response().build(
                Container(
                    success=False,
                    client_id=0,
                    reject_reason=reason
                )
            ) + unlocked_sector_magic
        )
        self.protocol.transport.write(rejection)
        self.protocol.transport.loseConnection()

    def on_connect_response(self, data):
        try:
            connection_parameters = connect_response().parse(data.data)
            if not connection_parameters.success:
                self.protocol.transport.loseConnection()
            else:
                self.protocol.player.client_id = connection_parameters.client_id
                self.protocol.player.logged_in = True
                self.logger.info("Player %s (UUID: %s, IP: %s) logged in" % (
                    self.protocol.player.name, self.protocol.player.uuid,
                    self.protocol.transport.getPeer().host))
        except:
            self.logger.exception("Exception in on_connect_response, player info may not have been logged.")
        finally:
            return True

    def after_world_start(self, data):
        world_start = packets.world_start().parse(data.data)
        if 'fuel.max' in world_start['world_properties']:
            self.logger.info("Player %s is now on a ship.", self.protocol.player.name)
            self.protocol.player.on_ship = True
        else:
            coords = world_start.planet['celestialParameters']['coordinate']
            parent_system = coords
            location = parent_system['location']
            l = location
            self.protocol.player.on_ship = False
            planet = Planet(parent_system['sector'], l[0], l[1], l[2],
                            coords['planet'], coords['satellite'])
            self.protocol.player.planet = str(planet)

    def on_client_disconnect(self, player):
        if self.protocol.player is not None and self.protocol.player.logged_in:
            self.logger.info("Player disconnected: %s", self.protocol.player.name)
            self.protocol.player.logged_in = False
        return True

    @permissions(UserLevels.ADMIN)
    def delete_player(self, data):
        name = " ".join(data)
        if self.player_manager.get_logged_in_by_name(name) is not None:
            self.protocol.send_chat_message(
                "That player is currently logged in. Refusing to delete logged in character.")
            return False
        else:
            player = self.player_manager.get_by_name(name)
            if player is None:
                self.protocol.send_chat_message(
                    "Couldn't find a player named %s. Please check the spelling and try again." % name)
                return False
            self.player_manager.delete(player)
            self.protocol.send_chat_message("Deleted player with name %s." % name)

    @permissions(UserLevels.ADMIN)
    def list_players(self, data):
        if len(data) == 0:
            self.format_player_response(self.player_manager.all())
        else:
            rx = re.sub(r"[\*]", "%", " ".join(data))
            self.format_player_response(self.player_manager.all_like(rx))

    def format_player_response(self, players):
        if len(players) <= 25:
            self.protocol.send_chat_message(
                "Results:\n%s" % "\n".join(
                    ["^cyan;%s: ^yellow;%s" % (player.uuid, player.colored_name(self.config.colors)) for player in
                     players]))
        else:
            self.protocol.send_chat_message(
                "Results:\n%s" % "\n".join(
                    ["^cyan;%s: ^yellow;%s" % (player.uuid, player.colored_name(self.config.colors)) for player in
                     players[:25]]))
            self.protocol.send_chat_message(
                "And %d more. Narrow it down with SQL like syntax. Feel free to use a *, it will be replaced appropriately." % (
                    len(players) - 25))
