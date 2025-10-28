class Xcloud < Formula
  desc "A command line interface for xCloud"
  homepage "https://github.com/maximbilan/xcloud"
  url "https://github.com/maximbilan/xcloud/releases/download/v0.1/xcloud-0.1.tar.gz"
  sha256 "882cda045449873ce251514228fc7f91edb98e30ef2ba904c408e82752227c8f"
  version "0.1"

  def install
    bin.install "xcloud"
  end
end
