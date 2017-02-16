IDA-ClrNative
=============

ClrNative is an IDAPython script which applies information stored in mixed managed/native assemblies to the native code being viewed in IDA. For example, this allows easy identification of functions which are directly callable by managed code ("exported" from native to managed). Normally, the result is obtaining full name and type information for code and data exposed to the interop layer of the CLR.

Requires latest python construct library from https://github.com/construct/construct/releases  
*Clarification*: The above comment was written years ago now. This script requires construct 2.5.x (NOT 2.8.x)