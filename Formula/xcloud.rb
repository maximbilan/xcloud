class Xcloud < Formula
  desc "A command line interface for xCloud"
  homepage "https://github.com/maximbilan/xcloud"
  url "https://github.com/maximbilan/xcloud/releases/download/v0.1/xcloud-0.1.tar.gz"
  sha256 "b5b3ed9e42b7b6fd528e8fb65d22a2ede1ecab4dda0d2f47e0e07158fb12daa3"
  version "0.1"

  def install
    bin.install "xcloud"
  end
end
