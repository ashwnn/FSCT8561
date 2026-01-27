1. What happens if the server crashes while the client is connected?
If the server crashes, the TCP connection breaks. The client will notice on the next `recv()` or `send()` as `recv()` returning empty bytes or an exception like connection reset/broken pipe.

2. How can the server handle multiple clients?
Use concurrency so each accepted connection gets its own handler, such as a thread, process, or `asyncio`. For a group chat, keep a list of connected clients and broadcast messages to them.

3. Why can `recv(1024)` split messages unexpectedly?
TCP is a byte stream, not message-based, so `recv(1024)` can return partial data or multiple messages at once. You need framing like a newline delimiter or a length prefix to reassemble messages correctly.

4. How would you add basic security (authentication, encryption) to this chat application?
Wrap sockets with TLS (`ssl`) to encrypt traffic and prevent eavesdropping. Add authentication by requiring a username/password or token (preferably with challenge-response) and store only salted password hashes server-side.

