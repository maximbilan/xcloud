# xcloud ☁️

A powerful command-line interface for Apple's Xcode Cloud, built in Rust. Manage your CI/CD workflows, build runs, and artifacts directly from your terminal.

## Features

- 🔍 **Interactive Browser**: Navigate through products, workflows, branches, and actions with an intuitive menu system
- 📦 **Product Management**: List and inspect your Xcode Cloud products
- ⚙️ **Workflow Operations**: View workflows, start builds, and monitor progress
- 🌿 **Branch Management**: List and work with repository branches
- 🏗️ **Build Control**: Start new build runs and track their status
- 📊 **Run Analytics**: View detailed build run information, artifacts, and test results
- 🔑 **Token Management**: Generate and manage App Store Connect API tokens
- 📋 **Raw Data Access**: Get detailed JSON information for debugging and automation

## Installation

### Homebrew

```bash
brew tap maximbilan/xcloud https://github.com/maximbilan/xcloud
brew install xcloud
```

### From Source

```bash
git clone https://github.com/yourusername/xcloud.git
cd xcloud
cargo build --release
```

The binary will be available at `target/release/xcloud`.

### Using Cargo

```bash
cargo install xcloud
```

## Configuration

xcloud requires App Store Connect API credentials. Set these environment variables:

```bash
export XCLOUD_ISSUER="your-issuer-id"           # App Store Connect Issuer ID
export XCLOUD_KEY_ID="your-key-id"              # App Store Connect API Key ID  
export XCLOUD_P8="your-private-key-content"     # Contents of your .p8 private key
```

### Getting Your Credentials

1. **Issuer ID**: Found in App Store Connect under "Users and Access" → "Keys" → "App Store Connect API"
2. **Key ID**: The identifier for your API key
3. **Private Key**: The contents of your downloaded `.p8` file (either the full PEM format or just the base64 content)

## Usage

### Interactive Mode (Default)

Simply run `xcloud` to enter the interactive browser:

```bash
xcloud
```

This will guide you through:
1. Selecting a product
2. Choosing a workflow  
3. Picking a branch
4. Performing actions (start builds, view runs, etc.)

### Command Line Interface

#### Product Management

```bash
# List all Xcode Cloud products
xcloud products

# Get detailed information about a specific product
xcloud product-info --product <product-id>
```

#### Workflow Operations

```bash
# List workflows for a product
xcloud workflows --product <product-id>

# Get detailed workflow information
xcloud workflow-info --workflow <workflow-id>

# List recent build runs for a workflow
xcloud runs --workflow <workflow-id>
```

#### Branch Management

```bash
# List branches for a product's repository
xcloud branches --product <product-id>
```

#### Build Operations

```bash
# Start a new build run
xcloud build-start --workflow <workflow-id> --branch <branch-id>
```

#### Run Analysis

```bash
# Get detailed information about a build run
xcloud run-info --run <run-id>

# List artifacts for a build run
xcloud artifacts --run <run-id>

# View test results for a build run
xcloud test-results --run <run-id>
```

#### Token Management

```bash
# Generate and print a short-lived App Store Connect token
xcloud token
```

### Global Options

- `-v, --verbose`: Enable verbose output for debugging
- `-h, --help`: Show help information
- `--version`: Show version information

## Examples

### Starting a Build

```bash
# 1. List your products
xcloud products

# 2. List workflows for your product
xcloud workflows --product abc123-def456-ghi789

# 3. List branches
xcloud branches --product abc123-def456-ghi789

# 4. Start a build
xcloud build-start --workflow xyz789-abc123 --branch main
```

### Monitoring Build Progress

```bash
# Check recent runs for a workflow
xcloud runs --workflow xyz789-abc123

# Get detailed run information
xcloud run-info --run run-abc123-def456

# Download artifacts
xcloud artifacts --run run-abc123-def456
```

### Using in CI/CD

```bash
# Generate a token for other tools
TOKEN=$(xcloud token)

# Use the token with curl
curl -H "Authorization: Bearer $TOKEN" \
     https://api.appstoreconnect.apple.com/v1/ciProducts
```

## Interactive Mode Guide

The interactive mode provides a hierarchical navigation system:

1. **Products** → Select your Xcode Cloud product
2. **Workflows** → Choose a workflow to work with
3. **Branches** → Pick a branch for builds
4. **Actions** → Perform operations like:
   - Start build runs
   - View recent runs
   - Inspect run details
   - Download artifacts
   - View test results

Use arrow keys to navigate and Enter to select. Type to filter options.

## API Integration

xcloud uses the official App Store Connect API v1. It automatically handles:

- JWT token generation and caching
- API pagination
- Error handling and retries
- Rate limiting compliance

## Troubleshooting

### Common Issues

**"Missing env XCLOUD_ISSUER"**
- Ensure your environment variables are set correctly
- Check that your `.p8` key file is properly formatted

**"Failed to parse XCLOUD_P8 as an EC PKCS#8 private key"**
- Make sure your private key is in the correct format
- xcloud accepts both full PEM format and base64-only content

**"No products available"**
- Verify your API key has the necessary permissions
- Check that you have Xcode Cloud products set up in App Store Connect

### Debug Mode

Use the `--verbose` flag to see detailed API requests and responses:

```bash
xcloud --verbose products
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup

```bash
git clone https://github.com/yourusername/xcloud.git
cd xcloud
cargo build
cargo test
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [Rust](https://www.rust-lang.org/) for performance and reliability
- Uses [clap](https://github.com/clap-rs/clap) for command-line argument parsing
- Powered by [reqwest](https://github.com/seanmonstar/reqwest) for HTTP requests
- Interactive menus provided by [dialoguer](https://github.com/mitsuhiko/dialoguer)

---

**Made with ❤️ for the iOS development community**
