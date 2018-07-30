use std::io::{stdin, stdout, BufRead, Result, Write};

use shared::handle_command;

fn main() -> Result<()> {
    let mut bytes = vec![];
    let mut out = String::new();
    let mut inp = String::new();

    print!("> ");
    stdout().flush()?;

    loop {
        inp.clear();

        let stdin = stdin();
        stdin.lock().read_line(&mut inp)?;

        handle_command(&inp, &mut bytes, &mut out, None, None).unwrap();

        print!("{}> ", out);
        stdout().flush()?;
    }
}
