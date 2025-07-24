The issue is that your library is built only as a `cdylib`, which is intended for FFI and doesn’t include the Rust metadata needed for the Rust compiler to resolve symbols within the same package. In a `cdylib`, the Rust symbols are stripped out so that it can be used from non‑Rust code (e.g. Python via FFI), but then your binary in `src/bin` can’t import it as a normal Rust crate.

To fix this, you can add the `rlib` crate type along with `cdylib` in your Cargo.toml. For example:

```toml
[lib]
crate-type = ["rlib", "cdylib"]
```

This tells Cargo to build both a Rust library (`.rlib`) that your binary can use internally and a C-compatible shared library (`.so`) for FFI.

After making this change, in your binary (e.g. `src/bin/cfm.rs`) you can simply use:

```rust
use cfm_lib::auth_beaver_triples;
```

and it should compile without the unresolved import error.

### Summary

- **cdylib only:** Strips Rust metadata, so the binary cannot import the crate.
- **Adding rlib:**  
  Update `[lib]` section in Cargo.toml to:
  ```toml
  [lib]
  crate-type = ["rlib", "cdylib"]
  ```
  Now the binary can import your library normally, and you'll still produce a .so for FFI.