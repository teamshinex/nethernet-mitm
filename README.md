# nethernet-mitm

Play on a friend's Minecraft Bedrock world over the internet without port forwarding.

Three programs work together:

| Program | Runs on | Port forward |
| --- | --- | --- |
| `relay` | a server reachable from the internet | one TCP port (default 7000) |
| `host` | the PC of the player who has the world | none |
| `join` | the PC of each player who wants to join | none |

```
Minecraft (host) ── host ──► relay ◄── join ── Minecraft (joiner)
```

## Setup

Requires Node.js 18.5 or newer.

```
npm install
```

## Usage

### 1. Start the relay

```
npm run relay -- --token <host-token>
```

Check it from outside: `http://<public ip>:7000/health`

### 2. Share the world (host)

Open the world to LAN in Minecraft, then:

```
npm run host -- --relay <relay ip> --id myworld --token <host-token>
```

Give joiners the relay address, the id (`myworld`) and, if set, the `--password`.

### 3. Join the world (joiner)

```
npm run join -- --relay <relay ip> --id myworld
```

In Minecraft: **Servers → Add Server**, address = this PC's IP, port `19132`.

## Options

Each program lists all its options with `--help`:

```
npm run relay -- --help
npm run host -- --help
npm run join -- --help
```

## Files created at runtime

| File | Created by | Notes |
| --- | --- | --- |
| `relay-ids.json` | relay | registered host ids |
| `host-agent-state.json` | host | secret that owns your id — keep it private |
| `identity-key.pem` | join | local server identity key |

## License

`data/bedrock-1.26.60-protocol.json` comes from minecraft-data (MIT); see `data/LICENSE-minecraft-data`.
