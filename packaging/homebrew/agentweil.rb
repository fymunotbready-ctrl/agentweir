# Template for a Homebrew tap (a separate repo named homebrew-agentweil).
# Builds from source, matching the project's "no prebuilt binaries required" stance.
# After you publish a tagged release, set the url and sha256 below:
#   curl -L <url> | shasum -a 256
class Agentweil < Formula
  desc "Egress allowlist and tamper-evident audit log for AI agents (prototype)"
  homepage "https://github.com/YOURUSERNAME/agentweil"
  url "https://github.com/YOURUSERNAME/agentweil/archive/refs/tags/v0.2.0.tar.gz"
  sha256 "REPLACE_WITH_SHA256_OF_THE_TARBALL"
  license "MIT"

  def install
    system "make"
    bin.install "agentweil"
  end

  test do
    assert_match "PASS", shell_output("#{bin}/agentweil selftest")
  end
end
