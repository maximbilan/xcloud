class Xcloud < Formula
  desc "A command line interface for xCloud"
  homepage "https://github.com/maximbilan/xcloud"
  url "https://github.com/maximbilan/xcloud/releases/download/v0.1/xcloud-0.1.tar.gz"
  sha256 "54d9d161c46d27a30eb393e4f8f224cd42bfe80d3d46011d2c75de5b8221adfe"
  version "0.1"

  def install
    bin.install "xcloud"
  end
end
