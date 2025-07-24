### **Purpose of `#[no_mangle]` in Rust FFI**
The `#[no_mangle]` attribute **prevents Rust from renaming the function during compilation** so that it can be called **from external programs** (like Python, C, or other languages via FFI).

---

### **Why is This Needed?**
Rust applies **name mangling** to function names by default. This means:
- Rust **changes function names** during compilation to include metadata (like type signatures and modules).
- The compiled function name is **not predictable**, making it **impossible** to call from external programs.

For example, without `#[no_mangle]`, a Rust function like this:

```rust
pub extern "C" fn my_function() { }
```

might get compiled into something like:

```
_ZN3my_function17h3d21407e9eb7e512E
```

**This name is unpredictable and cannot be used in Python!** 🚨

---

### **How `#[no_mangle]` Helps**
When you add `#[no_mangle]`, Rust keeps the function name **unchanged** in the compiled output.

```rust
#[no_mangle]
pub extern "C" fn my_function() { }
```

Now, the compiled function name remains **exactly**:

```
my_function
```

This makes it **callable from C, Python (via ctypes), or any other language** that supports FFI.

---

### **When Should You Use `#[no_mangle]`?**
✅ Use it **only on `extern "C"` functions** that need to be accessible **outside Rust** (e.g., via FFI).  
✅ Apply it **to all Rust functions exposed to Python/C** in shared libraries (`.so` / `.dll` / `.dylib`).  

---

### **Example: Using `#[no_mangle]` in Rust and Calling It from Python**
#### **Rust Code:**
```rust
#[no_mangle]
pub extern "C" fn add_numbers(a: i32, b: i32) -> i32 {
    a + b
}
```

#### **Python Code to Call the Rust Function:**
```python
import ctypes

# Load the Rust shared library
rust_lib = ctypes.CDLL("./target/release/librust_lib.so")

# Define function signature
rust_lib.add_numbers.argtypes = [ctypes.c_int, ctypes.c_int]
rust_lib.add_numbers.restype = ctypes.c_int

# Call the function
result = rust_lib.add_numbers(3, 7)
print(f"Result from Rust: {result}")  # Output: 10
```

Without `#[no_mangle]`, **this will not work** because Python won’t find `add_numbers` by name.

---

### **Does `#[no_mangle]` Affect Performance?**
No, it only affects **function naming** and does **not** impact performance.

---

### **Summary**
| Feature          | Without `#[no_mangle]` | With `#[no_mangle]` |
|-----------------|----------------------|---------------------|
| Function Naming | Mangled (unreadable) | Unchanged (C-style) |
| Callable from Python | ❌ No | ✅ Yes |
| Required for FFI? | ❌ No (but makes calling hard) | ✅ Yes |

🚀 **Conclusion:** Always use `#[no_mangle]` when exposing functions in Rust for FFI!