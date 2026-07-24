# Historical EMBER v2 reference

This environment is deliberately separate from endpoint runtime. It requires
the official Elastic EMBER repository at commit
`d97a0b523de02f3fe5ea6089d080abacab6ee931`.

```bash
git clone https://github.com/elastic/ember.git reference/ember
git -C reference/ember checkout d97a0b523de02f3fe5ea6089d080abacab6ee931
docker build -f reference/Dockerfile.ember-v2 -t ember-v2-reference .
docker run --rm \
  -v "$PWD/reference/ember:/ember" \
  -v "$PWD/samples:/samples:ro" \
  -v "$PWD/tests/golden:/golden" \
  -e PYTHONPATH=/ember \
  ember-v2-reference --file /samples/authorized.exe --output-dir /golden
```

If `lief==0.9.0` or the pinned scientific stack fails to build, treat that as a
failed reference build. Do not substitute another LIEF version.

