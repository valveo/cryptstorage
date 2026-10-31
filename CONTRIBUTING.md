# Contributing

Thanks for looking at CryptStorage. Contributions are welcome and appreciated.

## Changes: please send them back

CryptStorage is licensed under the [GNU AGPL v3.0 only](LICENSE). If you run a changed version for
others, the license already requires you to offer them your source code; **please also share the
change here as a pull request.** It helps everyone who uses the project, you included (you no
longer have to carry the change in your own fork).

Fixes and improvements that are small and focused get reviewed fastest. For a larger change, open
an issue first so the direction can be agreed before you spend the time.

## Security problems

Do **not** report vulnerabilities in a public issue or pull request. Follow [SECURITY.md](SECURITY.md).

## Setting up

```
pip install -r requirements-dev.txt
python -m pytest -q
python -m pyflakes api cryptdaemon tests
cd cryptclient && go vet ./... && go test ./...
```

A change that fixes a bug should come with a test that fails without the fix. Anything that touches
keys, tokens, authentication or the daemon socket needs extra care: say in the pull request what
you changed and what you checked. Parts that need root, FUSE or a Docker host are described at the
end of the README; if you could only test a change with mocks, say so.

## Licensing of contributions

By submitting a contribution you confirm that you wrote it (or have the right to submit it) and
that it may be used under the project's license, the GNU AGPL v3.0 only. The copyright in your
contribution stays with you, but you also grant Matti Mieskonen (@valveo) a perpetual, worldwide,
royalty-free right to use, change and license your contribution under other terms as well,
including a commercial license. This keeps it possible to offer CryptStorage under a separate commercial
license (see the README) without asking every contributor afterwards. If you do not agree, say so
in the pull request before it is merged.
