## polluteagain

Oops!... Pollution again — this time in Python.

> Prototype pollution has a cousin in the Python world: **class pollution**.

The server is written in Python and merges your JSON input into a server-side object. The flag is
only returned to an authenticated **admin** user.

In this level, you are required to identify and exploit the **class pollution** vulnerability to
escalate your privileges from a normal user to admin, and retrieve the flag.

Two notes:
- The obvious traversal keys have been blacklisted — you will need to find another route to reach
  what you want.
- The server hands you something on `/data` that you must make sense of before your forged
  credentials will be accepted. Reconnaissance is part of the challenge.
