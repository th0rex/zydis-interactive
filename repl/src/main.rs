use std::io::{stdin, stdout, Result, Write};

use shared::handle_command;

fn main() -> Result<()> {
    let mut bytes = vec![];
    let mut out = String::new();
    let mut inp = String::new();

    print!("> ");
    stdout().flush()?;

    loop {
        inp.clear();

        if stdin().read_line(&mut inp)? == 0 {
            // On Ctrl+D we exit.
            return Ok(());
        }

        handle_command(&inp, &mut bytes, &mut out, None, None).unwrap();

        print!("{}> ", out);
        stdout().flush()?;
    }
}
