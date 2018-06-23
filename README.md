# sman

sman(ssh manager) is ssh client/host manager for CLI (linux, macOS)

I got to a point where i was strugling to keep up with huge amount of ssh servers i have to administer, especially in dynamic dev envinronment. Realy nice extention for your terminal

While being bored i decided to develop lightweight ssh client to maintain list of ssh servers/credentials/keys that i'm working with.


Features:
Runs under non-sudo user, including Vault server
Dont have to search for IPs or credentials anymore. Neat list of ssh hosts that you work with everyday
Connecting to your remote hosts is a matter of selecting host from the list
Gain sudo permissions as soon as you connect to the host.
Intergated with Hashi Vault to keep passwords, keys and other data secure. 
Let sman handle rsa-keys(generated and stored in Vault), just point to the server where you want to install public key.


Product is one night and pack of redbull old, so pretty much completely untested.


hello world
