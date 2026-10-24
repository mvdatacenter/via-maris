# via-maris

`via-maris` is a package gateway. Package managers fetch through it instead of straight from public registries, and it checks each version before serving it.

A version listed as malicious in published advisory data is refused, and so is a version younger than a configured release-age hold unless the configuration carries an exception for it. The refusal names the package, the version, and the advisory or age that refused it. When the gateway cannot run a check, the install is refused.

The gateway keeps nothing that cannot be fetched again from upstream. Its behaviour comes entirely from configuration: the list of upstream registries it fronts and the policy applied to each.

The name comes from the Via Maris, the Way of the Sea, the ancient road from Egypt through Galilee to Damascus.

## Status

There is no code yet. The design is being written first, and this repository holds its license and project terms until the implementation starts.

## License

`via-maris` is free software under the GNU Affero General Public License, version 3. See [LICENSE](LICENSE).

Copyright MV Data.

## Security

Report vulnerabilities privately as [SECURITY.md](SECURITY.md) describes, not in a public issue.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
