# disable-protocols-and-ciphers-on-servers
 This PowerShell script is designed to adjust security protocols and cryptographic settings across multiple computers by modifying specific registry keys. 

This PowerShell script is designed to adjust security protocols and cryptographic settings across multiple computers by modifying specific registry keys. Here’s what it does in detail:

Targets Multiple Computers: The $computers array holds the names of the computers the script will modify. The array can be populated with one or more computer names.

Disables Older Protocols:

The script disables older, less secure protocols like SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1 by setting relevant registry keys to disable them for both the server and client sides. The DisableSecurityProtocol function is used for this purpose.
Removes and Disables Weak Ciphers:

It clears out and disables weak cipher algorithms (such as RC4, DES, and Triple DES) by deleting their registry keys or setting their Enabled property to 0. This ensures only stronger ciphers are available.
Disables Static Key Ciphers:

It disables static key exchange algorithms like PKCS and Diffie-Hellman (DH) using the disableStaticKeyCiphers function, improving security by enforcing dynamically generated keys.
Enforces Stronger Key Length for Diffie-Hellman:

The dhKeyLength function ensures that Diffie-Hellman keys are at least 2048 bits, providing greater encryption strength.
Enables Strong Cryptography for .NET:

The TurnOnStrongCrypto function sets a registry key that enables strong cryptographic protocols for .NET applications. This is applied to both 32-bit and 64-bit versions.
Enables TLS 1.2:

The script specifically enables TLS 1.2, considered more secure than the older protocols. This is done through the EnableSecurityProtocol function.
Logging and Output:

Throughout, the script provides output messages, indicating progress and actions taken on each computer.
