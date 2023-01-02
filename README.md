# UniCipher 𓂀 
A smiple utf8 cipher.

Don't use for anything that actually requires good security.
This is a toy.

# Usage
UniCipher can be used to encrypt or decrypt text, to and from UTF-8 characters:

    $ unicipher --encrypt "hello"
    㨥㬬寀
    $ unicipher --decrypt "㨥㬬寀"
    hello

Input is also accept from stdin or from a file via the `--input-file` option.
By default, the results are sent to stdout but can be sent to a file via the `--output-file` option.

# Building
To build unicipher, `cargo build`. No other dependencies are needed.
