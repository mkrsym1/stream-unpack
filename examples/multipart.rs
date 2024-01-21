use std::{fs::{self, File, OpenOptions}, path::PathBuf, cell::RefCell, io::{Write, self}};

use stream_unpack::zip::{ZipUnpacker, ZipDecodedData, read_cd};

fn main() {
    let output_dir = "unpack";

    let archives = [
        "multipart/archive_m.z01",
        "multipart/archive_m.z02",
        "multipart/archive_m.z03",
        "multipart/archive_m.z04",
        "multipart/archive_m.z05",
        "multipart/archive_m.z06",
        "multipart/archive_m.z07",
        "multipart/archive_m.zip"
    ].map(fs::read).map(Result::unwrap);
    let sizes = archives.iter().map(Vec::len).collect::<Vec<_>>();

    let _ = fs::remove_dir_all(output_dir);

    let central_directory = read_cd::from_provider(
        &sizes,
        false,
        |pos, length| {
            println!("Requested {length} bytes at {pos}");
            Ok(archives[pos.disk][(pos.offset)..(pos.offset + length)].to_owned())
        }
    ).unwrap().sort();

    let current_file: RefCell<Option<File>> = RefCell::new(None);

    let mut unpacker = ZipUnpacker::new(central_directory, sizes);
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

    for archive in archives {
        unpacker.update(archive).unwrap();
    }

    println!("\nDone!");
}
