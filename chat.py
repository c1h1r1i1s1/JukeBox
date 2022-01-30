from fbchat import Client, Message
from fbchat.models import *
import cred
import json
import requests
import base64
from urllib.parse import urlparse
import http.server
import os

global auth_code
global log_status
if len(cred.refresh_token) < 1:
    log_status = False
else:
    log_status = True

# Website Server for receiving auth code details
class LoginServer(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        global auth_code
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(bytes("<html><head><title>App Authorised Successfully</title></head>", "utf-8"))
        self.wfile.write(bytes("<body>", "utf-8"))
        self.wfile.write(bytes("<p>Thanks for authorising!</p>", "utf-8"))
        self.wfile.write(bytes("</body></html>", "utf-8"))
        query = urlparse(self.path).query
        auth_code = query.split("=")[1]
        print("\nAuth Code received")

class EchoBot(Client):

    def onMessage(self, author_id, message_object, thread_id, thread_type, **kwargs):
        if thread_type == ThreadType.USER:
            if author_id == self.uid and not message_object.text is None and "connect" == message_object.text.lower():
                print("Connect received")
                access_token = self.connect(thread_id, thread_type)
            elif message_object.text is None:
                print("Fetching last message...")
                message = client.fetchThreadMessages(thread_id=thread_id, limit=1)
                if not message is None:
                    try:
                        link = message[0]["extensible_attachment"]["story_attachment"]["url"]
                        if not link is None and len(link) > 2:
                            self.thread_id = thread_id
                            self.thread_type = thread_type
                            if self.checker(link):
                                self.adder(link)
                    except TypeError:
                        pass
                    except:
                        raise
    def checker(self, text):
        global log_status
        if "spotify" in text and "track" in text:
            print("Found link")
            if not log_status:
                print("Not logged in to Spotify!")
                self.send(Message(text="Haven't logged into Spotify yet! Contact Admin"), thread_id=self.thread_id, thread_type=self.thread_type)
                return False
            return True
        return False

    def connect(self, thread_id, thread_type):
        global auth_code
        global log_status
        scope = "user-read-playback-state user-modify-playback-state"
        redirect_uri = "http://raspberrypi.local:8080/"
        auth_url = "https://accounts.spotify.com/authorize"
        token_url = 'https://accounts.spotify.com/api/token'
        auth_response = requests.get(auth_url, {
            'scope': scope,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'client_id': cred.client_id,
        })
        print("Sending validation link...")
        self.send(Message(text=auth_response.request.url), thread_id=thread_id, thread_type=thread_type)
        hostName = "0.0.0.0"
        serverPort = 8080
        webServer = http.server.HTTPServer((hostName, serverPort), LoginServer)
        print("Server started")
        try:
            while 1:
                webServer.handle_request()
                break
        except KeyboardInterrupt:
            pass
        webServer.server_close()
        print("Server stopped. Collecting Token...")

        encoded_client = "{}:{}".format(cred.client_id, cred.client_secret)
        encoded_client = encoded_client.encode('ascii')
        encoded_client = base64.b64encode(encoded_client)
        encoded_client = encoded_client.decode('ascii')
        headers = {
            'Authorization': 'Basic {}'.format(encoded_client),
            'Content-Type': "application/x-www-form-urlencoded"
        }
        auth_response = requests.post(token_url, {
            'redirect_uri': redirect_uri,
            'code': auth_code,
            'grant_type': "authorization_code",
        }, headers=headers)

        auth_response_data = auth_response.json()
        self.access_token = auth_response_data['access_token']
        self.refresh_token = auth_response_data['refresh_token']
        creds = open("cred.py", 'r')
        old_creds = creds.readlines()
        old_creds.pop()
        old_creds.append("refresh_token='{}'".format(self.refresh_token))
        new_creds = old_creds
        creds.close()
        creds2 = open("cred.py", "w")
        creds2.writelines(new_creds)
        creds2.close()
        print("Access Token Received\n")
        log_status = True

    def refresh(self):
        print("Refreshing Token...")
        token_url = 'https://accounts.spotify.com/api/token'
        encoded_client = "{}:{}".format(cred.client_id, cred.client_secret)
        encoded_client = encoded_client.encode('ascii')
        encoded_client = base64.b64encode(encoded_client)
        encoded_client = encoded_client.decode('ascii')
        self.refresh_token = cred.refresh_token
        headers = {
            'Authorization': 'Basic {}'.format(encoded_client),
            'Content-Type': "application/x-www-form-urlencoded"
        }
        auth_response = requests.post(token_url, {
            'refresh_token': self.refresh_token,
            'grant_type': "refresh_token",
        }, headers=headers)

        auth_response_data = auth_response.json()
        self.access_token = auth_response_data['access_token']
        print("Access Token Refreshed\n")

    def adder(self, text):
        print("Adding to que")
        text = text.split("track%2F")
        uri = text[1].split("%")[0]
        if '&' in uri:
            uri = uri.split('&')[0]
        print("URI is: ", end='')
        print(uri)

        dev_url = "https://api.spotify.com/v1/me/player/devices"
        try:
            headers = {
                'Authorization': 'Bearer {}'.format(self.access_token),
                'Content-Type': "application/json"
            }
        except AttributeError:
            self.refresh()
            headers = {
                'Authorization': 'Bearer {}'.format(self.access_token),
                'Content-Type': "application/json"
            }
        except:
            raise
        response = requests.get(dev_url, headers=headers)
        response = response.json()
        if "error" in response:
            if response["error"]["status"] == 401:
                self.refresh()
                headers = {
                    'Authorization': 'Bearer {}'.format(self.access_token),
                    'Content-Type': "application/json"
                }
                response = requests.get(dev_url, headers=headers)
                response = response.json()
        print("Getting device list...")
        active_found = False
        for device in response["devices"]:
            if device["is_active"]:
                active_found = True
                device_id = device["id"]
                print("Active device found")
                break
        if not active_found:
            print("Warning: No active player found. Adding to first")
            if len(response["devices"]) < 1:
                print("No players found! Returning...\n")
                return
            for device in response["devices"]:
                device_id = device["id"]
        print("Device selected\n")

        url = "https://api.spotify.com/v1/me/player/queue?uri=spotify%3Atrack%3A{}&device_id={}".format(uri, device_id)
        self.send(Message(text="Added to que"), thread_id=self.thread_id, thread_type=self.thread_type)
        response = requests.post(url, headers=headers)
        print("Add to que response: {}".format(response))

client = EchoBot(cred.user, cred.passw, logging_level=30)
client.listen()
