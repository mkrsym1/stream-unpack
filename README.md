# stream-unpacker
A small library for stream unpacking archives (e.g. downloading and unpacking simultaneously). Currently supports single, multipart and fake multipart (single archive cut into multiple files) ZIPs, uncompressed and compressed with DEFLATE. This library requires you to obtain a central directory of the ZIP you want to unpack first, and provides utilities for doing so conveniently.

## Example
See full examples in this repo.
```rust
let archive = fs::read("archive.zip").unwrap();

let central_directory = read_cd::from_provider(
    vec![archive.len()],
    false, // Determines whether to interpret it as a fake multipart (cut) archive
    |pos, length| Ok(archive[(pos.offset)..(pos.offset + length)].to_owned())
).unwrap();

let mut unpacker = ZipUnpacker::new(central_directory.sort(), vec![archive.len()], |data| {
    println!("Got data: {data}");
    // Do something useful with data. See full examples

    Ok(())
});

// You can provide an arbitrary amount of bytes at a time
// Make sure to advance the buffer exactly the amount of bytes returned
// All split archives (multipart and fake multipart) should be treated
// as a continuous stream of bytes from the first one to the last one
let (advanced, reached_end) = unpacker.update(archive).unwrap();

println!("Done!");
```

License: GPL v3
