//! # tls — does the handshake succeed, and is the certificate healthy?
//!
//! Mail uses TLS in two shapes: **STARTTLS** (connect in plaintext on 25/587,
//! then upgrade) and **implicit TLS** (encrypted from the first byte, 465).
//! This probe performs either handshake and returns the evidence the doctor
//! needs: did it succeed, which protocol version, who signed the
//! certificate, and how long until it expires (the 3am-outage question).
