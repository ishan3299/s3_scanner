# Contributing to S3 Scanner

Thank you for your interest in contributing to the S3 Scanner project! We welcome contributions from the community to make this tool safer, more robust, and more effective.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

1.  **Fork the Repository**: Create a fork of the repository on GitHub.
2.  **Clone the Fork**: `git clone https://github.com/YOUR_USERNAME/s3_scanner.git`
3.  **Create a Branch**: `git checkout -b feature/my-new-feature`
4.  **Make Changes**: Implement your feature or fix.
5.  **Test**: Ensure your changes work as expected.
6.  **Commit**: `git commit -m "Add some feature"`
7.  **Push**: `git push origin feature/my-new-feature`
8.  **Open a Pull Request**: Submit a PR to the `main` branch.

## Development Guidelines

-   **Safety First**: This tool MUST be non-destructive. Do not add any features that delete, modify, or aggressively scan targets.
-   **Client-Side Limitation**: The passive scanner must run entirely in the browser without backend dependencies.
-   **Code Style**:
    -   JavaScript: Use ES6+ features, clean indentation (4 spaces).
    -   Python: Follow PEP 8 guidelines.
    -   CSS: Keep it modular and use CSS variables.

## Reporting Bugs

Please use the [Bug Report Template](.github/ISSUE_TEMPLATE/bug_report.md) to report issues.
