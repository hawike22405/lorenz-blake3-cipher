# Contributing to Lorenz–BLAKE3 Image Cipher

Thank you for considering contributions to this research prototype!

## ⚠️ Important Notice

This is a **research prototype** with **no security proof**. It is **not** suitable for production use. Contributions should focus on:

- Reproducibility improvements
- Structural analysis and cryptanalysis
- Documentation and testing
- Bug fixes

## Before Contributing

1. **Read the paper**: `FIXED_PAPER.md` contains the research context and limitations
2. **Understand the scope**: This cipher does not claim IND-CPA, INT-CTXT, or 256-bit security
3. **Check existing issues**: See if your idea or bug report already exists

## How to Contribute

### Bug Reports

Include:
- Rust version (`rustc --version`)
- Steps to reproduce
- Expected vs. actual behavior
- Minimal reproducible example

### Code Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run tests: `cd code && cargo test --release --locked`
5. Run clippy: `cd code && cargo clippy --release --locked`
6. Commit with a clear message
7. Push and open a pull request

### Documentation

- Update `ARCHITECTURE.md` for design changes
- Update `README.md` for usage changes
- Update `FIXED_PAPER.md` for research claims

## Code Style

- Follow Rust idioms and clippy recommendations
- Document all public functions
- Add unit tests for new functionality
- Keep functions small and focused

## Security Disclosure

This is a research cipher. If you find a cryptanalytic result, please open an issue to discuss it responsibly.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
