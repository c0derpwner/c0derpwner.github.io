---
title: Huntress_Tickler_3
published: true
---


#### Initial Analysis

The challenge provides a Rust binary for analysis. Opening the binary in IDA Free and decompiling it reveals the typical Rust structure with a main function. Upon dynamic execution of the binary, the user is presented with the following prompt:


```bash
What is my favorite sha256 hash?
```


Since this binary expects user input that needs to be validated for some activity, the analysis focuses on identifying where user input gets validated by examining the overall code structure and setting strategic breakpoints on potentially relevant code patterns.

#### Validation Function

To find the validation routine, breakpoints are placed on interesting code patterns in the disassembled view of IDA Free, particularly on `if` statements and function calls that could be involved in validation logic. Executing the binary in IDA’s built-in debugger and stepping through the code flow reveals the following sequence:

1. The first several `if` statements are reached before user input is even collected, ruling them out as the validation check
2. After providing test input and continuing execution, a breakpoint is hit at a significant `if` statement

This critical `if` statement contains the validation logic (note that functions have been renamed for better readability):

```c
if ( xor_prng_validate_input(args1, (__int64)args2, args3) )
	{ 
		may_msg_print(&v62, (__int64)&args1_prt, 4921); 
		if ( (_QWORD)v62 == 0x8000000000000000uLL ) 
			goto LABEL_113; 
		hObject.m256i_i64[2] = (__int64)p_p_hObject; 
		*(_OWORD *)hObject.m256i_i8 = v62;
		p_hObject = &hObject;
		v57 = (__int64)sub_11D0; 
		*(_QWORD *)&v62 = &unk_240A478;
		*((_QWORD *)&v62 + 1) = 2; v65 = 0;
	....
	
```

The validation occurs through a call to `xor_prng_validate_input` at `BASE+23EDDF0`. The function receives three arguments in the following registers:

- First argument (RSI / args1): Pointer to a structure containing encrypted data
- Second argument (R13 / args2): Pointer to the user’s input
- Third argument (RDX / args3): Length of the input

The `xor_prng_validate_input` function implements a custom stream cipher using a PRNG-like algorithm:


```c
bool __fastcall xor_prng_validate_input(__int64 a1, __int64 a2, __int64 a3)
{
  unsigned int v3; // seed (from struct)
  __int64 v4 = 0;
  if ( *(_QWORD *)(a1 + 16) != a3 )
    return 0;
  v3 = *(_DWORD *)(a1 + 24);
  do
  {
    if (a3 == v4) break;
    uint32_t v6 = v3 * ((__ROR4__(v3, v3) & 0xFFFFFFFC) + 1) + (__ROL4__(~v3, 4) | 1);
    uint32_t v7 = v6 >> ((v3 >> (~(_BYTE)v3 & 0xF)) % 0x18);
    v3 = v6;
    if ((*(_BYTE *)(a2 + v4) ^ (unsigned __int8)v7) != *(_BYTE *)(*(_QWORD *)(a1 + 8) + v4))
      return false;
    ++v4;
  } while (1);
  return true;
}
```
The function operates by:

1. Verifying the input length matches the expected length stored in the structure at offset `+16`
2. Extracting a seed value from the structure at offset `+24`
3. Generating a pseudo-random keystream using bitwise operations (ROR, ROL, XOR)
4. XORing each input byte with the corresponding keystream byte
5. Comparing the result against pre-encrypted data pointed to by offset `+8` in the structure

To understand the data structure being used and where it comes from, the decompiled code before the validation call is examined. Tracing where `args1` originates from reveals it comes from a lookup function just a few lines above the validation:

```c
v1 = lookup_struct_entry_by_id(&args1_ptr, 4922);
if ( !v1 )
  goto LABEL_113;
args1 = v1;
args2 = utf8_skip_ws_and_return_ptr(v79, v80);
v5 = args3;
if ( (unsigned __int8)xor_prng_validate_input(args1, args2, args3) )
```

The `args1` structure is retrieved by `lookup_struct_entry_by_id`, which takes a pointer to an array of structures (`args1_ptr`) and an index value (`4922`) used to identify the specific entry. Analyzing this lookup function reveals how the structure array is organized:

```c
__int64 __fastcall lookup_struct_entry_by_id(__int64 struct_array_ptr, int search_id)
{
  __int64 current_entry_ptr;
  __int64 remaining_bytes;
  __int64 found_entry;
  bool id_matches;

  current_entry_ptr = *(_QWORD *)(struct_array_ptr + 8) - 40LL;
  remaining_bytes = 40LL * *(_QWORD *)(struct_array_ptr + 16);
  while ( remaining_bytes )
  {
    found_entry = current_entry_ptr + 40;
    remaining_bytes -= 40;
    id_matches = *(_DWORD *)(current_entry_ptr + 72) == search_id;
    current_entry_ptr += 40;
    if ( id_matches )
      return found_entry;
  }
  return 0;
}
```

This function searches through an array of 40-byte structures. The `struct_array_ptr` parameter points to a structure that contains the base address and count of entries in the array. The function iterates through these entries, comparing the ID field at offset `+32` (shown by `current_entry_ptr + 72` which equals `current_entry_ptr + 40 + 32`) until it finds the entry matching the `search_id` of `4922`.

#### Dynamic Analysis

To extract the encrypted data and seed, a breakpoint is set at the call to `xor_prng_validate_input` in the IDA debugger. When the breakpoint is hit after providing test input, the register values reveal the function arguments:

- **RSI (first argument / args1)**: `0x000001C283DB7878` - pointer to the Entry structure
- **R13 (second argument / args2)**: pointer to user input
- **RDX (third argument / args3)**: input length

Examining the memory at the Entry structure pointer (RSI) reveals the structure fields:

- **`*(RSI + 0x8)`**: pointer to encrypted buffer
- **`*(RSI + 0x10)`**: buffer length (64 bytes)
- **`*(RSI + 0x18)`**: seed value `0x133A`

Following the pointer at offset `+0x8` to the encrypted buffer and dumping 64 bytes yields:

```python
encrypted_hex = (
    'F5 40 C3 B7 2D EE C9 CE 88 F6 C1 56 48 14 59 0B '
    '6A 38 52 79 EF B6 33 7F EE C8 61 5E B7 DC 95 7F '
    '62 1B D9 87 9E C6 90 CD 3B F1 65 C2 56 E2 07 67 '
    'AB D0 EA 94 3E 1C F6 B6 2C 24 F2 23 E9 19 97 32'
)
```

#### Implementing the PRNG Algorithm

The PRNG algorithm must be replicated exactly as implemented in the binary to generate the correct keystream. Three helper functions are needed:

- **`ror()`** - Performs a right bitwise rotation, shifting bits to the right with wraparound
- **`rol()`** - Performs a left bitwise rotation, shifting bits to the left with wraparound
- **`generate_stream()`** - Implements the custom PRNG algorithm using rotate operations and arithmetic to produce the keystream bytes

With the encrypted data, seed, and PRNG implementation, the complete decryption script can be written:

```python
#!/usr/bin/env python3

def ror(value, count, bits=32):
    """Rotate right operation"""
    count %= bits
    return ((value >> count) | (value << (bits - count))) & ((1 << bits) - 1)

def rol(value, count, bits=32):
    """Rotate left operation"""
    count %= bits
    return ((value << count) | (value >> (bits - count))) & ((1 << bits) - 1)

def generate_stream(seed, length):
    """Generate PRNG keystream matching the binary's algorithm"""
    output = []
    for _ in range(length):
        ror_val = ror(seed, seed)
        v6 = seed * ((ror_val & 0xFFFFFFFC) + 1) + (rol(~seed & 0xFFFFFFFF, 4) | 1)
        shift_amount = (~seed & 0xF)
        shift = (seed >> shift_amount) % 0x18 if shift_amount < 32 else 0
        stream_byte = (v6 >> shift) & 0xFF
        output.append(stream_byte)
        seed = v6 & 0xFFFFFFFF  # Keep seed 32-bit
    return output

# Encrypted data extracted from memory
encrypted_hex = (
    'F5 40 C3 B7 2D EE C9 CE 88 F6 C1 56 48 14 59 0B '
    '6A 38 52 79 EF B6 33 7F EE C8 61 5E B7 DC 95 7F '
    '62 1B D9 87 9E C6 90 CD 3B F1 65 C2 56 E2 07 67 '
    'AB D0 EA 94 3E 1C F6 B6 2C 24 F2 23 E9 19 97 32'
)

encrypted = bytes.fromhex(encrypted_hex.replace(' ', ''))
seed = 0x133A

# Generate keystream
stream = generate_stream(seed, len(encrypted))

# Decrypt by XORing encrypted data with keystream
plaintext = bytes([b ^ s for b, s in zip(encrypted, stream)])
print(plaintext.decode('utf-8', errors='replace'))
```

**Expected input:**

```fallback
a4ec6d39192922bdec0e310db3dda25f21f1d7e8e9e68cfebc156553e4123b03
```

#### Stage 2 extraction

Providing the correct input string prints the success message “Thank you, Bingus! But our princess is in another castle!” however there is no additional hint on how go get the flag. To understand the binary’s behavior after successful validation, Process Monitor (Procmon) from Sysinternals Suite is used to observe file system and registry activity during execution.

Running the binary under Procmon with the correct input reveals a suspicious entry:
![[Pasted image 20251104124609.png]]

```bash
Operation: CreateFile
Path: C:\Users\ladmin\AppData\Roaming\Exodus
Result: NAME NOT FOUND
Desired Access: Read Attributes, Synchronize
```

In Windows, when `CreateFile` is called with `Desired Access: Read Attributes, Synchronize` on a path without a file extension, this indicates a directory existence check rather than an attempt to open a file. The `NAME NOT FOUND` result means the program is checking for the `Exodus` directory, which does not exist.

This directory can be created manually in the expected APPDATA location. Running the binary again with the correct input now produces different behavior. Procmon shows successful file operations, and examining the Exodus directory reveals that a new file has been created:
![[Pasted image 20251104124641.png]]

The file `rust-tickler-3-stage-2.exe` appears in the directory. Based on the dynamic analysis and the appearance of the second stage, it can be deduced that the second-stage binary is embedded in encrypted form within the first stage. After successful input validation and directory verification, the program decrypts this embedded data and writes the resulting executable to disk. The second stage binary does not execute automatically and must be run manually to continue the challenge.

---

### Stage 2: rust-tickler-3-stage-2.exe

#### Initial Analysis

The second stage binary `rust-tickler-3-stage-2.exe` is opened in IDA Free for decompilation and analysis. Following a similar methodology to Stage 1, the analysis begins by locating the main function and examining the overall code structure. An initial execution without breakpoints confirms the executable prompts for user input “Okay for real this time, the flag is actually going to be the password. I definitely not in the icon file…”, indicating another validation challenge.

To locate the validation logic, breakpoints are set on interesting code sections, particularly conditional statements and function calls that could be involved in input verification. After providing test input and continuing execution through the debugger, two critical functions are discovered that handle the cryptographic validation process.

#### Identifying the Validation Functions

Through dynamic execution with breakpoints the validation logic is traced to a function at `BASE+1CC0`, renamed to `compare_function` for clarity. This function acts as a wrapper that extracts parameters from two structures and passes them to the actual validation routine at `BASE+1E30`, renamed to `validate_and_check`.

Analysis of `validate_and_check` reveals it encrypts the user’s input using AES-256-CBC and compares the result against pre-computed expected ciphertext stored in memory. The validation succeeds only if the encrypted input matches the expected ciphertext exactly, block by block.

**The compare_function**

```c
void compare_function(undefined8 *param_1, undefined4 *param_2)
{
  validate_and_check(
      param_1 + 6,                      // scratch_ctx
      *param_1,                         // expected_ciphertext_ptr
      param_1[1],                       // expected_padded_len (48)
      param_1[2],                       // key_ptr
      *(undefined4 *)(param_1 + 3),     // key_len (32)
      param_1[4],                       // iv_ptr
      *(undefined4 *)(param_1 + 5),     // iv_len (16)
      *param_2,                         // user_input_ptr
      param_2[2]);                      // user_input_len
  return;
}
```

This function acts as a wrapper, extracting fields from two parameter structures:

- `param_1`: A structure containing cryptographic material and validation parameters
- `param_2`: A structure containing the user’s input and its length

By analyzing the memory dump at `param_1` (RCX register) during dynamic analysis, the structure layout is determined as follows:

```c
// Structure 1 - Cryptographic Material (verified via memory dump)
param_1[0] -> expected_ciphertext_ptr  (48 bytes of AES ciphertext)
param_1[1] -> expected_padded_len      (48 bytes input length after PKCS#7 padding)
param_1[2] -> key_ptr                  (32 byte AES-256 key)
param_1[3] -> key_len                  (32 bytes)
param_1[4] -> iv_ptr                   (16 byte initialization vector)
param_1[5] -> iv_len                   (16 bytes)
param_1[6] -> scratch_ctx              (Context buffer for encryption operations)

// Structure 2 - User Input
param_2[0] -> user_input_ptr           (Pointer to users input string)
param_2[2] -> user_input_len           (Length of users input)
```

**The validate_and_check Function**

This function implements the cryptographic validation using AES-256-CBC. Before any encryption occurs, it performs input length validation:  
(Note: The following code snippet contains only the relevant portions necessary for understanding the validation logic, not the complete function implementation)

```c
__int64 __fastcall validate_and_check(
        __int64 *scratch_ctx,
        __int64 expected_ciphertext_ptr,      // Pointer to expected ciphertext
        size_t expected_padded_len,           // Expected length after padding (48)
        __int64 key_ptr,                      // Pointer to AES-256 key
        unsigned __int64 key_len,             // Key length (32 bytes)
        __int64 iv_ptr,                       // Pointer to IV
        unsigned __int64 iv_len,              // IV length (16 bytes)
        __int64 user_input_ptr,               // Pointer to users input
        size_t user_input_len)                // Length of users input
{
  block_size = get_divisor_value(scratch_ctx);
  if ( !block_size )
    goto LABEL_ERROR;
  // Calculate expected padded length from user input
  calculated_padded_len = block_size + user_input_len - (user_input_len % block_size);
  if ( expected_padded_len != calculated_padded_len )
    goto LABEL_ERROR;
  // Initialize crypto context with key and IV
  initialize_crypto_ctx__(
      (DWORD *)expected_encrypted_chunk,
      *scratch_ctx,
      0,
      key_ptr,
      key_len,
      iv_ptr,
      iv_len);

  // Encryption loop - process input in blocks
  for (block_offset = 0; block_offset < expected_padded_len; block_offset += block_size)
  {
    // Encrypt current block of user input
    encrypt_buffer_evp(&v23, &v21, user_input_ptr, block_offset,
                       (__int64)expected_encrypted_chunk, 2 * block_size);

    // Compare encrypted block against expected ciphertext
    if ( memcmp(expected_encrypted_chunk, (const void *)(user_input_ptr + v18), value_16) )
      break;
  }
}
```

The validation function operates as follows:

1. **Length Validation**: Calculates the expected padded length from the user’s input
2. **Context Initialization**: Sets up the AES-256-CBC encryption context using the 32-byte key and 16-byte IV
3. **Block-by-block Encryption**: Encrypts the user’s input one 16-byte AES block at a time
4. **Comparison**: After encrypting each block, compares it against the corresponding block of expected ciphertext stored in memory
5. **Success Condition**: All three encrypted blocks must match the expected ciphertext for validation to succeed

To recover the expected input, the expected ciphertext can be extracted from memory and decrypted using the key and IV, directly revealing the expected input.

#### Dynamic Analysis

To extract the cryptographic material (AES key, IV, and expected ciphertext), two breakpoints are placed in the IDA debugger within the validation flow.

**Breakpoint 1: initialize_crypto_ctx__**

A breakpoint at the call to `initialize_crypto_ctx__` (`BASE+2300`) captures the cryptographic parameters being initialized.

- First 4 arguments: `RCX`, `RDX`, `R8`, `R9`

**Register values at breakpoint:**

```fallback
RCX: 0x30                      ; arg1: Buffer size (48 bytes)
RDX: 0x6                       ; arg2: Algorithm identifier (AES-256)
R8:  0x30                      ; arg3: Key material length (48 bytes)
R9:  0x00007FF7285FD128        ; arg4: Pointer to key+IV material
```

Examining the memory at `R9` (address `0x7FF7285FD128`) and dumping 48 bytes reveals the cryptographic material:

```fallback
00007FF7285FD128: D4 C3 94 86 FD F0 42 83  F5 D9 64 36 BA 68 EA 1C
00007FF7285FD138: 4F 41 94 79 6A F8 2D 0F  8E ED 7C 12 F5 3F A0 7C
00007FF7285FD148: 53 9F B3 1E 1C C1 34 42  42 0D 03 93 97 E9 17 77
```

Since the total length is 48 bytes and AES-256 requires a 32-byte key and2025-11-04-rust-tickler-3.md 16-byte IV, the data can be split as follows:

**Extracted cryptographic material:**

- **AES-256 Key** (bytes 0-31):
    
    ```fallback
    D4 C3 94 86 FD F0 42 83 F5 D9 64 36 BA 68 EA 1C
    4F 41 94 79 6A F8 2D 0F 8E ED 7C 12 F5 3F A0 7C
    ```
    
- **Initialization Vector (IV)** (bytes 32-47):
    
    ```fallback
    53 9F B3 1E 1C C1 34 42 42 0D 03 93 97 E9 17 77
    ```
    

**Breakpoint 2: memcmp - Extracting Expected Ciphertext**

A breakpoint at the `memcmp` (`BASE+2031`) call reveals where encrypted blocks are compared against the expected ciphertext. This function is called once per AES block (16 bytes), so multiple hits are expected as the program validates each block.

**x64 calling convention for memcmp:**

- `RCX`: Pointer to first buffer (the encrypted user input)
- `RDX`: Pointer to second buffer (expected ciphertext)
- `R8`: Number of bytes to compare

**Register values at breakpoint:**

```fallback
RCX: 0x0000001B6078F980    ; The encrypted input block
RDX: 0x00007FF7285FD0F8    ; Expected ciphertext block 1
R8:  0x10                  ; 16 bytes (one AES block)
```

The value at `RCX` shows what the test input was encrypted to (not needed). The essential data is at `RDX` the expected ciphertext address.

Since the expected input is 38 bytes and AES operates on 16-byte blocks, the total encrypted size with PKCS#7 padding is 48 bytes (3 blocks). Dumping 48 bytes from the ciphertext address reveals the complete expected ciphertext:

```fallback
00007FF7285FD0F8: CB 58 4B 62 03 5D 13 8F  77 BC 98 10 F0 0F 1A 20
00007FF7285FD108: 20 70 0F 8F BF 0D 75 DC  A3 FD 71 08 5F 14 67 CD
00007FF7285FD118: E9 D0 5F 1F 83 BB C7 6B  7D 9B EB 42 F7 51 00 95
```

**Complete expected ciphertext (48 bytes):**

```fallback
Block 1 (0-15):   CB 58 4B 62 03 5D 13 8F 77 BC 98 10 F0 0F 1A 20
Block 2 (16-31):  20 70 0F 8F BF 0D 75 DC A3 FD 71 08 5F 14 67 CD
Block 3 (32-47):  E9 D0 5F 1F 83 BB C7 6B 7D 9B EB 42 F7 51 00 95
```

#### Decryption Script

With all the cryptographic material extracted (AES-256 key, IV, and expected ciphertext), the solution involves decrypting the expected ciphertext using the extracted key and IV, which directly reveals the flag.

```python
#!/usr/bin/env python3
from Crypto.Cipher import AES

# Expected ciphertext extracted from memory at 0x7FF7285FD0F8
# Captured from the memcmp breakpoint - this is what the encrypted
# input is compared against
ciphertext = bytes.fromhex(
    'CB584B62035D138F77BC9810F00F1A20'  # Block 1
    '20700F8FBF0D75DCA3FD71085F1467CD'  # Block 2
    'E9D05F1F83BBC76B7D9BEB42F7510095'  # Block 3
)

# AES-256 Key extracted from initialize_crypto_ctx__ call
# Found in R9 register (0x7FF7285FD128), bytes 0-31
key = bytes.fromhex(
    'D4C39486FDF04283F5D96436BA68EA1C'
    '4F4194796AF82D0F8EED7C12F53FA07C'
)

# IV (Initialization Vector) extracted from initialize_crypto_ctx__ call
# Found in R9 register (0x7FF7285FD148), bytes 32-47
iv = bytes.fromhex(
    '539FB31E1CC13442420D039397E91777'
)

print("[*] Crypto material extracted from memory:")
print(f"    Key:        {key.hex()}")
print(f"    IV:         {iv.hex()}")
print(f"    Ciphertext: {ciphertext.hex()}")
print()

# Decrypt using AES-256-CBC
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext)

# The answer is 38 bytes, rest is PKCS#7 padding (0x0A repeated 10 times)
answer = plaintext[:38].decode('ascii')
print(f"[+] {answer}")
```

**Output:**

```bash
[*] Crypto material extracted from memory:
    Key:        d4c39486fdf04283f5d96436ba68ea1c4f4194796af82d0f8eed7c12f53fa07c
    IV:         539fb31e1cc13442420d039397e91777
    Ciphertext: cb584b62035d138f77bc9810f00f1a2020700f8fbf0d75dca3fd71085f1467cde9d05f1f83bbc76b7d9beb42f7510095

[+] flag{fb8de641f383151222845d9b991a17c2}
```
