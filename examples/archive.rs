use std::{fs::{self, File, OpenOptions}, path::PathBuf, cell::RefCell, io::{Write, self}};

use stream_unpack::zip::{ZipUnpacker, ZipDecodedData, read_cd};

fn main() {
    let output_dir = "unpack";
    let archive = fs::read("archive.zip").unwrap();
    let _ = fs::remove_dir_all(output_dir);

    let central_directory = read_cd::from_provider(
        vec![archive.len()],
        false,
        |pos, length| {
            println!("Requested {length} bytes at {pos}");
            Ok(archive[(pos.offset)..(pos.offset + length)].to_owned())
        }
    ).unwrap().sort();

    let current_file: RefCell<Option<File>> = RefCell::new(None);

    let mut unpacker = ZipUnpacker::new(central_directory, vec![archive.len()]);
    unpacker.set_callback(|data| {
        match data {
            ZipDecodedData::FileHeader(cdfh, _) => {
                println!();

                let mut path = PathBuf::from(output_dir);
                path.push(&cdfh.filename);

                if !cdfh.is_directory() {
                    print!("New file: {}", cdfh.filename);
                    io::stdout().flush()?;

                    fs::create_dir_all(path.parent().unwrap())?;

                    *current_file.borrow_mut() = Some(
                        OpenOptions::new()
                        .create(true)
                        .write(true)
                        .open(path)?
                    );
                } else {
                    print!("New directory: {}", cdfh.filename);
                    io::stdout().flush()?;

                    fs::create_dir_all(path)?;
                }
            },

            ZipDecodedData::FileData(data) => {
                print!(".");
                io::stdout().flush()?;

                current_file.borrow().as_ref().unwrap().write_all(data)?;
            }
        }

        Ok(())
    });

    unpacker.update(archive).unwrap();

    println!("\nDone!");
}
