#!/bin/bash

set -e

# Configuration
GITHUB_USER="your_github_username"
HOMEBREW_TAP_REPO="homebrew-tap"
PACKAGE_NAME="xcloud"
VERSION=$(grep "^version" Cargo.toml | sed 's/version = "\(.*\)"/\1/')

# 1. Build the release binary
echo "Building release binary..."
cargo build --release

# 2. Create a tarball of the binary
echo "Creating tarball..."
mkdir -p "target/release/${PACKAGE_NAME}-${VERSION}"
cp "target/release/${PACKAGE_NAME}" "target/release/${PACKAGE_NAME}-${VERSION}/"
tar -czf "target/release/${PACKAGE_NAME}-${VERSION}.tar.gz" -C "target/release" "${PACKAGE_NAME}-${VERSION}"

# 3. Create a new GitHub release and upload the tarball
echo "Creating GitHub release..."
gh release create "v${VERSION}" "target/release/${PACKAGE_NAME}-${VERSION}.tar.gz" --title "v${VERSION}" --notes "Release v${VERSION}"

# 4. Generate a Homebrew formula
echo "Generating Homebrew formula..."
FORMULA_URL="https://github.com/${GITHUB_USER}/${PACKAGE_NAME}/releases/download/v${VERSION}/${PACKAGE_NAME}-${VERSION}.tar.gz"
SHA256=$(shasum -a 256 "target/release/${PACKAGE_NAME}-${VERSION}.tar.gz" | awk '{print $1}')

cat > "${PACKAGE_NAME}.rb" <<EOF
class Xcloud < Formula
  desc "A command line interface for xCloud"
  homepage "https://github.com/${GITHUB_USER}/${PACKAGE_NAME}"
  url "${FORMULA_URL}"
  sha256 "${SHA256}"
  version "${VERSION}"

  def install
    bin.install "xcloud"
  end
end
EOF

# 5. Commit the formula to a Homebrew tap
echo "Committing formula to Homebrew tap..."
git clone "https://github.com/${GITHUB_USER}/${HOMEBREW_TAP_REPO}.git"
mv "${PACKAGE_NAME}.rb" "${HOMEBREW_TAP_REPO}/Formula/"
cd "${HOMEBREW_TAP_REPO}"
git add "Formula/${PACKAGE_NAME}.rb"
git commit -m "feat: Add ${PACKAGE_NAME} v${VERSION}"
git push

echo "Done!"
