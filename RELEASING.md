# Release checklist

1. Update `kVersion` in `src/main.cpp`, add a `CHANGELOG.md` entry.
2. `make test` passes locally on Linux. Push and confirm the **ci** workflow is green (check the macOS job too).
3. Tag and push: `git tag v0.2.0 && git push origin v0.2.0`. The **release** workflow builds Linux and macOS binaries and publishes them with `SHA256SUMS`.
4. Download one tarball and verify it: `sha256sum -c SHA256SUMS --ignore-missing`.
5. Test the install paths on a clean machine or VM: source build, `docker build -t agentwall .`, and the Compose example.
6. Homebrew: in the `homebrew-agentwall` tap repo, copy `packaging/homebrew/agentwall.rb`, set the tag URL and its sha256, then `brew install --build-from-source ./agentwall.rb && brew test agentwall`.
7. Update the website and README if commands changed. Post the release notes.
8. Later: add build provenance attestations and signed tags so security-minded users can verify where binaries came from.
