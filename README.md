


DESFire EV3

Initial Card Setup:
Store a unique secret key on each card (in secure element if using DESFire)
This key would be paired with a card identifier in your server database
The key never leaves the card


During Verification:
Phone reads UID + ATR
Server generates and sends a random challenge
Phone sends challenge to card
Card uses its stored secret to generate a response (HMAC of challenge + UID + ATR)
Phone sends this response back to server
Server verifies using stored secret

This way:
Each verification generates unique data
Replay attacks won't work because challenge changes each time
