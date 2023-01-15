# hmac_knock

Very secure port knocking server/client, using HMAC'd messages.

Port knocking is great for poking temporary holes in a firewall to let you in, without leaving daemons like sshd exposed permanently to the wild.

Although knocking raises the security bar a bit, regular knocking techniques are very easy to intercept and replay. hmac_knock solves that problem completely.

## How it works

hmac_knock server and client have a pre-shared secret. The client generates a message with the current timestamp (float64 epoch time) authenticated via HMAC with the secret. The message, 40 bytes in total, is sent via UDP to the server.

The server receives the UDP message, validates if the timestamp is within the allowable skew time and validates the HMAC authentication. If the message is valid, the server runs a configurable command with the source IP address as a parameter (to open the firewall), sleeps for a configurable amount of time and then runs another configurable command (to close the firewall).

## Security

Although the message is not encrypted, it is authenticated, so it cannot be tampered with.

The window of opportunity for a replay attack is very short and can be set in the server configuration file.

The server is completely stealth. It will never send anything over the network. It cannot be detected with port scanning techniques.

Messages are binary and look like random 40 bytes. Tools like Wireshark will have no idea what those messages are about.

The server uses async I/O, is very small, is written in Rust and is compiled statically. It can handle a very large amount of traffic with no problem. It will immediately ignore any message that is not 40 bytes long, with minimal CPU overhead.

## Notes

It’s imperative that both client and server have synchronized clocks, via NTP for example.
