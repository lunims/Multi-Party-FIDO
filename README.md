# Multi-Party-FIDO

This repository contains the code of my Bachelor Thesis with the title "Protecting FIDO Credentials using Multi and Threshold Signatures". In this Thesis we will implement a FIDO authenticator using threshold signatures. The idea is that each authenticator holds his own key share which he uses to generate its part of the signature on the FIDO challenge and once the specified threshold of sign shares is generated, we collect and forge them together to the full signature in order to authenticate within the FIDO server.

## Important Note

This Thesis acts like a proof of concept implementation. It does not provide a fully-fleshed security model nor is it the aim of this Thesis. The goal is to show that mutli-party signatures are possible within the FIDO standard and evaluate the benefits and problems which might arise using this kind of approach.

## FIDO2 Library

We use the python-fido2 library by Yubico. By using this lib we can assure that our approach lies within the FIDO standard. (https://github.com/Yubico/python-fido2)

## Usage

The provided demos can be run via following command. t and n are parameters for threshold and participating players: 
"python3 main.py demo t n"

## External Libraries

In this repository there might be code snippets which are based on external repos. These snippets are marked by comments in the code with corresponding links to the source.
