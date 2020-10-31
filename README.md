# extender

I was thinking of fuzzing my Wi-Fi signals using python.
Scapy (https://scapy.net) is the defacto standard for packet manipulation in python.
Therefore, it seemed like a reasonable place to begin.

The next thing I did was reference the Wi-Fi standards as defined by IEEE.

When I contrasted the IEEE standards with the Scapy source, what I found was a little surprising.

Scapy only supported a very small subset of Information Elements (IEs) as defined by the standards.

There are a lot of open source Wi-Fi fuzzers available on the internet that use Scapy. This means that a large number of IEs are not fuzzed using publically available fuzzers.

To remedy this, I decided to 'extend' Scapy's capability by supporting all of the defined IEEE IEs as defined by the standard.

Enjoy
:)

