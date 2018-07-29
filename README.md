# Zydis Interactive

This provides a shared library to interactively disassemble data with zydis. Currently this consists of a discord bot and very soon there will be a REPL as well. You can see the discord bot in action on the [zyantific discord](https://discord.gg/pJaSX3n).

## Building
You need a recent rust nightly installation. Then simply do
```
cargo build --all --release
```

## Running
To run the discord bot do:
```
export DISCORD_TOKEN="YOUR_TOKEN_HERE"
cd zycord_serenity
cargo run --release
```

