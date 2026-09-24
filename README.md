# Kerberos-Logon-Network-File-Access-Analysis
A packet-level analysis of Kerberos authentication and SMB file access in a Windows Active Directory environment, built on a 3-VM domain (Domain Controller, file server, and client) with all authentication and file-transfer traffic captured and dissected in Wireshark.

## Objective

Set up a functioning Active Directory domain and capture, packet-by-packet, the full Kerberos logon process (AS-REQ → AS-REP → TGS-REQ → TGS-REP) plus subsequent SMB file access — proving which parts of the exchange are encrypted, which are sent in plaintext, and what encryption algorithm protects the rest.

## Lab Environment

| Machine | Role | Static IP | Domain |
|---|---|---|---|
| Domain Controller | AD DS + DNS + KDC | 172.16.0.121 | crypto.com |
| File Server | Shared folder host (`Files_Nikul`) | 172.16.0.122 | crypto.com |
| Client | Initiates logon + file access | 172.16.0.123 | crypto.com |  

<img width="936" height="745" alt="image" src="https://github.com/user-attachments/assets/4a2bf60b-5459-4841-a78f-f16388d531d1" />
<img width="995" height="600" alt="image" src="https://github.com/user-attachments/assets/259ab845-09f1-44c9-831d-915ce7f1f69b" />

- 3x Windows Server 2019 VMs, domain name `crypto.com`
- Two domain user accounts (`testuser1` on the file server, `testuser2` on the client) created in a dedicated `LabUsers` OU
- File server shares a folder (`Files_Nikul`) with Read/Write granted to `testuser2`

<img width="937" height="575" alt="image" src="https://github.com/user-attachments/assets/321ab803-61c0-4911-ae0e-6546943b7bb6" />

- Client's DNS points to the DC (172.16.0.121) so Kerberos SPN resolution and domain lookups work correctly
- Wireshark installed on all three VMs to capture traffic at each hop

## Part 1 — Capturing the Kerberos Logon

Filtered Wireshark on the DC for `kerberos` and captured all four stages of authentication when `testuser2` logged into the domain from the client:

<img width="990" height="556" alt="image" src="https://github.com/user-attachments/assets/5d236c28-32b8-4b10-9156-8bd80e9e112c" />

**1. AS-REQ (Authentication Service Request)** — client → DC
Client sends its username (`testuser2`) and a list of supported encryption types (AES256-CTS-HMAC-SHA1-96, RC4-HMAC, DES-CBC-CRC) to request a Ticket Granting Ticket (TGT). Includes a nonce to prevent replay attacks.

**2. AS-REP (Authentication Service Reply)** — DC → client
DC returns the TGT plus an encrypted session key. The ticket and session key are wrapped in `enc-part`, encrypted with AES256-CTS-HMAC-SHA1-96 — the cipher text is unreadable without the key.

<img width="990" height="556" alt="image" src="https://github.com/user-attachments/assets/4191187a-4fca-4448-a321-217f065a9e32" />

**3. TGS-REQ (Ticket Granting Service Request)** — client → DC
Using the TGT obtained above, the client requests a service ticket for the file server, authenticating itself via an AP-REQ built from the session key — no plaintext credentials are sent.

<img width="877" height="626" alt="image" src="https://github.com/user-attachments/assets/d034c880-9adf-4d12-99be-b5c42e08b4f8" />

**4. TGS-REP (Ticket Granting Service Reply)** — DC → client
DC issues an encrypted service ticket scoped to the file server (`testuser2ws.crypto.com`), again wrapped in AES256-encrypted `enc-part`.

<img width="876" height="623" alt="image" src="https://github.com/user-attachments/assets/0d09c919-d3d8-40ca-8262-dfd8ec675fc0" />

### What's encrypted vs. plaintext in the Kerberos exchange

| Field | Encrypted? |
|---|---|
| Username (CName: `testuser2`) | **Plaintext** — visible in every request |
| Realm (`CRYPTO.COM`) | Plaintext |
| Supported encryption types | Plaintext (negotiation only) |
| TGT contents / session key (`enc-part`) | **Encrypted** (AES256-CTS-HMAC-SHA1-96) |
| Service ticket contents (`enc-part`) | **Encrypted** (AES256-CTS-HMAC-SHA1-96) |
| User password | Never transmitted, at any stage |

This confirms Kerberos's core property: identity claims travel in the open, but everything that could grant access (tickets, session keys) is symmetrically encrypted and unreadable in the capture.

## Part 2 — Capturing File Access (SMB2)

Filtered for `smb || tcp.port == 445` and accessed the shared folder `\\172.16.0.122\Files_Nikul` from the client, then downloaded a 1KB test file.

Captured sequence:
1. **TCP handshake** (SYN/SYN-ACK/ACK) between client and file server
2. **Negotiate Protocol** — client and server agree on SMB2 dialect/capabilities
3. **Session Setup** — client authenticates the session (signing required); the security blob here carries the Kerberos ticket obtained in Part 1
4. **Tree Connect** — client connects to the `Files_Nikul` share
5. **Ioctl requests** — queries for network interface info and DFS referrals
6. **Read Request / Read Response** — client reads the file; server returns the raw data
7. **GetInfo Request/Response** — file metadata retrieved
8. **Close Request/Response** — file handle closed

### Proof the file payload is unencrypted

The **Read Response** packet contains the literal file contents in the SMB2 data payload. Decoding the hex bytes directly reveals the plaintext:

> `This is the new test file that we are going to transfer`

This confirms that while the Kerberos authentication layer is encrypted, the SMB file transfer itself carries data in the clear (no SMB encryption was enabled), meaning anyone capturing this traffic could read file contents directly from the payload.

## Key Takeaways

- Traced the full Kerberos ticket-granting flow (AS-REQ/AS-REP/TGS-REQ/TGS-REP) at the packet level and identified exactly which fields are encrypted vs. plaintext
- Demonstrated that Kerberos protects credentials and tickets via AES256 symmetric encryption while usernames and realm names remain visible for routing/lookup purposes
- Showed that transport-layer authentication security (Kerberos) does not automatically mean data-in-transit is encrypted — SMB file payloads were fully readable in the capture, highlighting why SMB signing/encryption is a separate, necessary control
- Built and administered a working 3-node Active Directory domain from scratch, including DNS, OU structure, shared folder permissions, and static network configuration

## Tools Used
Windows Server 2019 (Active Directory Domain Services, DNS), Wireshark

## Packet Capture
The full Wireshark capture used for this analysis is available in this repo: [`Kerberos.zip`](./Kerberos.zip) & [`WS-kbrs.zip`](./WS-kbrs.zip) — open it in Wireshark and filter on `kerberos` or `smb` to follow the exact exchange described above.

*Full report with annotated packet captures available on request.*
