# pg_bech32

This is a basic bech32 encode/decode PostgreSQL extension (stripped down from [pg_bitcoin_address](https://github.com/whitslack/pg_bitcoin_address) - making it a bit more generic bech32 encoder/decoder extension. Most of the files are untouched from original repository, removing everything other than references for bech32 itself.

> Complete credit for original work for this extension should go to [whitslack](https://github.com/whitslack)

## Building

You need pkg-config and PostgreSQL installed. Then building and installing this extension is simply clone the repo, go to the folder and run the below:

```
make
sudo make install
```

## Instantiating

You can instantiate the extension in your default schema:

```sql
=> CREATE EXTENSION pg_bech32;
CREATE EXTENSION
```

Or you can create a dedicated schema to host the extension:
```sql

=> CREATE EXTENSION pg_bech32 WITH SCHEMA grest;
CREATE EXTENSION

```

## Functions

### Bech32/Bech32m encoding/decoding

* **<code>b32_encode(<em>pre</em> text, <em>bytea</em> text)</code> → `text`**  
    Encodes a bit bytea string using Bech32 with the given human-readable prefix.
* **<code>b32_decode(encodedstr text)</code> → `bytea`**
    Decodes bech32 encoded string to bytea
* **`bech32_hrp(text)` → `text`**  
    Returns the human-readable prefix of the given Bech32/Bech32m encoding.
    * `bech32_hrp('pool12fclephansjkz0qn339w7mu9jwef2ty439as08avaw7fuyk56j6')` → `pool`

