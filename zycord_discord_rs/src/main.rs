#![deny(bare_trait_objects)]

use std::env;

use arrayvec::ArrayVec;

use discord::model::{Event, Message};
use discord::{Discord, Error};

use shared::{handle_command, CommandResult};

fn handle_message(
    discord: &Discord,
    msg: Message,
    bytes: &mut ArrayVec<[u8; 1024]>,
    out: &mut String,
) {
    if msg.author.bot {
        return;
    }

    match handle_command(
        &msg.content,
        bytes,
        out,
        Some(2000 - 6),
        Some("```x86asm\n"),
    ) {
        Some(x) => {
            if let CommandResult::Disassembled(x) = x {
                if x {
                    out.push_str("...");
                }

                out.push_str("```");
            }

            discord
                .send_message(msg.channel_id, &out, "", false)
                .expect("could not send discord message");
        }
        _ => {}
    }
}

fn main() {
    let token = env::var("DISCORD_TOKEN").expect("expected token");
    let discord = Discord::from_bot_token(&token).unwrap();

    let (mut conn, _) = discord.connect().unwrap();

    // So we don't allocate and free all the time.
    let mut s = String::new();
    let mut bytes = ArrayVec::new();

    loop {
        match conn.recv_event() {
            Ok(Event::MessageCreate(msg)) => handle_message(&discord, msg, &mut bytes, &mut s),
            Ok(_) => {}
            Err(Error::Closed(code, body)) => {
                println!("gateway closed with code {:?}: {}", code, body);

                let (new_conn, _) = discord.connect().expect("reconnect failed");
                conn = new_conn;
            }
            Err(e) => println!("Error: {}", e),
        }
    }
}
