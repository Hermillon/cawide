## Description

Please include a summary of the changes and the relevant motivation or context.

## Type of Change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Maintenance / refactoring

## Verification & Testing

Describe the tests you ran to verify your changes and provide instructions or command outputs:
- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets --locked -- -D warnings`
- `cargo nextest run --workspace --locked`
- `cargo deny check`

## Developer Certificate of Origin (DCO)

- [ ] I certify that all commits in this pull request comply with the Developer Certificate of Origin (DCO) and have been signed off using `git commit -s`.
