# CipherChaos in C

A simple Windows console messaging project written in one C file.

## Features

- FIFO queue for outgoing messages.
- Linked list for message history.
- Hash table for finding messages by ID.
- Basic XOR encryption with a shared key.
- TCP messaging between two console windows or two PCs.
- Simulated pendulum values using `rand()`.

## Run

Open `CipherChaosSimple.exe` twice.

**Receiver window**

1. Choose `2` for Receiver.
2. Enter a key, for example `8`.
3. Choose `4` to wait for messages.

**Sender window**

1. Choose `1` for Sender.
2. Enter the same key, `8`.
3. Enter `127.0.0.1` if both windows are on the same PC.
4. Choose `4` to add a message.
5. Choose `6` to send the front message or `7` to send the entire queue.

Use `1` for history, `2` to search by ID, and `3` to display hash buckets. On the sender, `5` displays the queue. Choose `4` on the receiver again before the next send operation.

For two PCs on the same network, use the receiver's IPv4 address and allow TCP port `5057` through its firewall.

## Build

Using MinGW GCC on Windows:

```bat
gcc main.c -o CipherChaosSimple.exe -lws2_32
```

In Code::Blocks, open **Settings > Compiler > Linker settings** and add `-lws2_32` under **Other linker options**, then build and run.

XOR is for demonstration, not secure messaging. History is kept in memory. Restart both programs for a fresh session because message IDs start at 1.

made with ❤️ by aarya
