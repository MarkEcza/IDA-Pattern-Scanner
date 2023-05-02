# IDA-Pattern-Scanner

## Overview

The IDA-Pattern-Scanner is a C++ header & source file that implements a basic IDA signature pattern scanner using the Boyer Moore Horspool algorithm. It allows users to scan for specific signatures in a given module, and retrieve the result as a handle to the memory address where the pattern was found.

## Usage

To use the IDA-Pattern-Scanner, you must first create an instance of the `pattern` class, specifying the name of the module you wish to scan for signatures. Then, you can call the `scan` function on the `pattern` object, passing in the name of the signature and an array of bytes representing the signature. The `get_result` function will return a handle to the memory address where the signature was found.

```c++
    // Scan for the signature "8B C3 33 D2 C6 44 24 20" in Demo.exe
    auto signature_1 = pattern("Demo.exe").scan("My Signature", "8B C3 33 D2 C6 44 24 20").get_result().as<uint64_t*>(); 

   // get_result() returns a handle object which can be further edited.
   
   .add(X)
   .sub()
   .rip()

```

Not that this is a crude scanner and should be treated as such.
