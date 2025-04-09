# omdoh (a modern instant messaging server)
omdoh is designed to be a modern-times instant messaging server to replace old, unmaintained servers.

## Features
* Uses TLS to encrypt all communications
* Quite easy to make a client (JSON to receive messages)
* Uses Flask as a HTTP server.

## Setup
To setup an omdoh server, you need to create an ssl certificate named `server.pem`. Here is an example:

```openssl req -new -x509 -days 365 -nodes -out server.pem -keyout server.pem```

omdoh uses the following packages: `socket` `ssl` `threading` `json` `uuid` `datetime` `flask: Flask, request, jsonify`, chances are that you need to install them.

Then run the omdoh.py file, which will start the server.

## Example testing usage

To create an account, you need to send a POST request to `/register` with the following JSON:
```json
{
    "username": "username",
    "password": "password"
}
```
More will be documented soon. For now, you can check out `exclient.py` to see how to make a client.


