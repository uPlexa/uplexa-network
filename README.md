# PlexaNet

Plexanet is a private, decentralized and pseudospoofing resistant overlay network for the internet. Plexanet uses a new routing protocol called UDAP (uPlexa Decentralized Application Protocol) based off of LLARP (Low Latency Anonymous Routing Protocol)

# [UDAP](https://udap.uplexa.com)
You may learn about the high level design of UDAP [here](doc/high-level.txt)
And you can read the UDAP protocol specification [here](doc/proto_beta.txt)

## Build

Please note development builds are likely to be unstable

Build requirements:

* CMake
* ninja
* libsodium >= 1.0.14
* C++ 11 capable C++ compiler


Building a debug build:

    $ make

## Running

You must configure the daemon yourself (for now)
