# prism

Web interface for binary static analysis using cleave and rizin.

## Usage

```bash
make build
PORT=8080 ./prism
```

Requires `cleave` (cleave analysis server) and `rizin` in PATH.

## Environment Variables

- `PORT` - HTTP port (default: 8080)
- `GCS_BUCKET` - GCS bucket for uploads (optional)
- `CLEAVE_PATH` / `CLEAVE_ADDR` - Path to cleave binary or server address

## Deploy

```bash
make deploy GCP_PROJECT=my-project GCS_BUCKET=my-bucket
```

## Development

```bash
make lint   # Run golangci-lint
make test   # Run tests
```
