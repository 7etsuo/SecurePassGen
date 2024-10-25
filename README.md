# SecurePassGen

A cryptographically secure password generator that provides high-entropy passwords with configurable requirements. Uses platform-native cryptographic APIs (BCrypt on Windows, Security framework on macOS, OpenSSL+getrandom on Linux) for secure random number generation.

## Security Features

- Uses cryptographically secure random number generation (CSPRNG)
- Implements rejection sampling to eliminate modulo bias
- Enforces minimum character type requirements
- Uses Fisher-Yates shuffle for uniform distribution
- Securely clears sensitive data from memory
- Platform-specific secure random number generation
- Configurable password requirements
- Entropy pool for efficient random number generation

## Building from Source

### Prerequisites

#### Windows
- MinGW-w64 or Microsoft Visual C++
- Windows SDK (for BCrypt)

#### macOS
- Xcode Command Line Tools
- Apple Security Framework (included in macOS)

#### Linux
- GCC or Clang
- OpenSSL development libraries
  - Ubuntu/Debian: `sudo apt-get install libssl-dev`
  - Fedora: `sudo dnf install openssl-devel`
  - Arch: `sudo pacman -S openssl`

### Compilation Instructions

#### Windows (MinGW-w64)
```bash
gcc password.c -o password.exe -lbcrypt
```

#### Windows (MSVC)
```bash
cl password.c bcrypt.lib
```

#### macOS
```bash
# For both Intel and Apple Silicon
gcc password.c -o password -framework Security
```

#### Linux
```bash
gcc password.c -o password -lcrypto
```

## Usage

```bash
./password <length>
```

Example:
```bash
./password 16
```

This will generate a password of specified length (minimum 12 characters) that includes:
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

## Configuration

You can modify the following defines in `password.c`:
```c
#define MAX_PASSWORD_LENGTH 128
#define MIN_PASSWORD_LENGTH 12
#define ENTROPY_MULTIPLIER 2
```

Password requirements can be adjusted by modifying the `PasswordRequirements` struct initialization in `main()`.

## Security Considerations

1. The generated passwords are intended for use as user credentials and should be treated as sensitive data.
2. The program securely clears sensitive data from memory after use.
3. The random number generation uses platform-specific cryptographic APIs.
4. The program enforces a minimum password length of 12 characters for security.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Repository Structure
```
SecurePassGen/
├── .gitignore
├── LICENSE
├── README.md
├── password.c
└── tests/
    └── test_password.c  # TODO: Add unit tests
```

## TODO

- Add unit tests
- Add CLI options for customizing password requirements
- Add password strength estimation
- Add option to generate multiple passwords
- Add option to exclude similar-looking characters
