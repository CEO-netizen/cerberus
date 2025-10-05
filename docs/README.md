# Cerberus

Cerberus is a packet flooding tool designed for network stress testing and educational purposes. It supports various types of attacks including TCP, UDP, ICMP, and more, for both IPv4 and IPv6.

## Warning

**This tool is intended for educational and authorized testing purposes only.** Unauthorized use of this tool to perform denial-of-service attacks or harm networks is illegal and unethical. Use at your own risk and ensure you have permission to test on any target systems.

## Features

- TCP attacks (SYN, ACK, FIN, RST, etc.)
- UDP flooding
- ICMP echo and router advertisement
- IPv4 and IPv6 support
- Customizable packet sizes and ports
- Multi-threaded for high performance

## Compilation

To compile the tool, ensure you have the necessary headers and libraries (e.g., libpthread).

```bash
gcc src/main.c -o cerberus -lpthread
```

## Usage

Run the tool with the appropriate flags. Use `-h` for help.

Example for a SYN flood on IPv4:

```bash
./cerberus -4 -T1 -h target_ip -t 60
```

For IPv6:

```bash
./cerberus -6 -T1 -h target_ipv6 -t 60
```

See the built-in help for all options:

```bash
./cerberus -h
```

## License

See LICENSE file for details.

## Disclaimer

The authors are not responsible for any misuse of this tool.
