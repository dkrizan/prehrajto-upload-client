# Prehraj.to Upload Client

Command-line uploader for Prehraj.to that mirrors the site's two-step upload flow. It supports both local files and streaming large remote files directly to the CDN without buffering or temp files.

## Features

- Authenticates via the standard login form
- Prepares upload metadata before sending data
- Streams multipart upload with constant memory usage
- Progress output with percent and upload speed
- Remote uploads use pure streaming; no temporary files

## Requirements

- Python 3.9+
- `requests`

Install dependencies:

```bash
pip install requests
```

## Usage

Local file upload:

```bash
python prehrajto_upload.py \
  --email you@example.com \
  --password yourpassword \
  --file /path/to/video.mp4
```

Remote file streaming upload:

```bash
python prehrajto_upload.py \
  --email you@example.com \
  --password yourpassword \
  --remote-url https://example.com/large-video.mp4
```

Override filename for remote uploads:

```bash
python prehrajto_upload.py \
  --email you@example.com \
  --password yourpassword \
  --remote-url https://example.com/large-video.mp4 \
  --remote-filename my-video.mp4
```

## Notes

- Remote uploads require the remote server to provide a valid `Content-Length`.
- The uploader uses pure streaming to avoid disk usage and keep memory constant.
- If authentication fails, verify credentials and account status.

## License

MIT
