#![deny(bare_trait_objects)]

use std::env;

use arrayvec::ArrayVec;

use serenity::model::channel::Message;
use serenity::model::gateway::{Game, GameType, Ready};
use serenity::prelude::*;

use shared::{handle_command, CommandResult};

struct Handler;

fn send(msg: &Message, s: &str) {
    if let Err(why) = msg.channel_id.say(s) {
        println!("error sending message: {}", why);
    }
}

impl EventHandler for Handler {
    fn message(&self, _: Context, msg: Message) {
        if msg.author.bot {
            return;
        }

        let mut bytes = ArrayVec::<[u8; 1024]>::new();
        let mut out = String::new();

        match handle_command(
            &msg.content,
            &mut bytes,
            &mut out,
            Some(2000 - 6),
            Some("```x86asm\n"),
        ) {
            Ok(Some(x)) => {
                if let CommandResult::Disassembled(x) = x {
                    if x {
                        out.push_str("...");
                    }

                    out.push_str("```");
                }

                send(&msg, &out);
            }
            Err(e) => send(&msg, &format!("internal error occured: {}", e.kind())),
            _ => {}
        }
    }

    fn ready(&self, ctx: Context, ready: Ready) {
        println!("{} is connected", ready.user.name);
        ctx.set_game(Game {
            kind: GameType::Playing,
            name: "https://zydis.re".into(),
            url: None,
        });
    }
}

fn main() {
    let token = env::var("DISCORD_TOKEN").expect("Expected a token in the environment");
    let mut client = Client::new(&token, Handler).expect("Err creating client");

    client.start_autosharded().unwrap();
}
