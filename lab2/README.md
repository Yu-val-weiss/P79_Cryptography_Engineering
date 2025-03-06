# Lab 2 - Authenticated key exchange

## Language

This lab is written in Go. Installation instructions are available [here](https://go.dev/doc/install).

## Repository Structure

```text
.
├── .dockerignore           # specifies which files the Docker container should ignore
├── Dockerfile              # specifies Docker container build, two step to keep image size small
├── Lab_Report_2.pdf        # lab report
├── README.md               # this file
├── cert_auth               # defines the certauth package (certification authority implementation)
│   ├── ca.go               # implementation of certauth
│   └── ca_test.go          # unit tests for certauth
├── go.mod                  # defines the lab2 module and its dependencies                
├── go.sum                  # checksums for module dependencies
├── run.sh                  # Docker runner
├── sigma                   # sigma protocol package
│   ├── client.go           # defines the various client types
│   ├── client_test.go      # tests these client types
│   ├── messages.go         # defines the messages that are sent at each protocol stage
│   ├── messages_test.go    # tests these messages
│   ├── sigma.go            # defines the core protocol methods
│   └── sigma_test.go       # tests the core protocol methods
├── sigmachat               # sigma-based secure chat package
│   ├── chat.go             # defines the chat package
│   └── chat_test.go        # tests the chat package
└── spake2                  # spake2 protocol package
    ├── client.go           # defines the client types used in the protocol
    ├── client_test.go      # tests these client types
    ├── init.go             # defines constants needed for the protocol
    ├── spake.go            # defines the core protocol methods
    └── spake_test.go       # tests the core protocol methods
```
