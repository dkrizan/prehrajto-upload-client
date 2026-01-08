"""
prehrajto_upload.py
--------------------

This module provides a simple command‑line interface (CLI) for uploading files to
the Czech streaming portal **Přehráj.to**.  The site uses a two‑step upload
process: first a small metadata request is made to obtain temporary
credentials, then the actual file is streamed to an external content
distribution network.  The logic implemented here mirrors the JavaScript
workflow used on the upload page.

**How it works**

1. **Login** – A session is established by posting the user’s email and
   password to the login form.  The same credentials are used for both the
   username and password by default, but the caller can override these.

2. **Prepare the upload** – Before a binary file can be sent, Přehráj.to
   expects a preparatory POST request to
   ``/profil/nahrat‑soubor?do=prepareVideo``.  The request body contains the
   file name, size, MIME type, an optional description and flags for private
   or erotic content.  In response the server returns a JSON object with
   ``project``, ``nonce``, ``params`` and ``signature`` fields which are
   required for the next step.  This behaviour can be seen in the page
   source where ``createNew`` posts the metadata and then builds a
   ``FormData`` object with these fields【346333217228061†L1515-L1533】.

3. **Upload the binary** – The actual video file is sent with a multipart
   request to ``https://api.premiumcdn.net/upload/``.  In addition to the
   binary (field name ``files``), the request includes the four values from
   the previous step and a ``response`` field set to ``JSON``【346333217228061†L1448-L1473】.  When the
   upload completes the API responds with a JSON document describing the
   newly created video; this information is returned to the caller.

**Usage**

Run the script directly from a POSIX shell.  The simplest invocation looks
like this:

```
python prehrajto_upload.py --email you@example.com \
    --password yourpassword \
    --file /path/to/video.mp4
```

You may also supply optional flags such as ``--description``, ``--private``
and ``--erotic``.  See ``python prehrajto_upload.py --help`` for details.

Note: this script requires the ``requests`` library.  It intentionally
does not hard‑code any credentials; instead it accepts them from the
command line to avoid leaking sensitive information.
"""

import argparse
import mimetypes
import os
import sys
import urllib.parse
from typing import Any, Callable, Dict, Iterable, Optional, Tuple

import requests


def login(session: requests.Session, email: str, password: str) -> None:
    """Authenticate to Prehraj.to.

    The login form is submitted to ``/prihlaseni?frm=login‑loginForm`` with
    fields ``email``, ``password``, ``remember_login`` and a hidden ``_do``
    value.  If authentication fails an exception is raised.

    Args:
        session: An existing :class:`requests.Session` for connection reuse.
        email: Email address (also used as username).
        password: Password associated with the account.

    Raises:
        RuntimeError: If authentication was not successful.
    """
    # Start by requesting the login page to obtain a session cookie.  Without
    # this the subsequent POST will be rejected.  The GET is not strictly
    # required by the current site implementation but is included for
    # completeness and future proofing.
    login_url = "https://prehrajto.cz/prihlaseni"
    resp = session.get(login_url)
    # A status code other than 200 indicates the site is blocking direct
    # access; in that case the script cannot continue.
    if resp.status_code != 200:
        raise RuntimeError(f"Failed to access login page (status {resp.status_code}).")

    # Prepare the payload.  The hidden `_do` value is required for the
    # server's Nette framework to route the request correctly【569201836121809†L584-L603】.
    payload = {
        "email": email,
        "password": password,
        "remember_login": "on",  # optional: automatically remember the session
        "_do": "login-loginForm-submit",
    }
    submit_url = "https://prehrajto.cz/prihlaseni?frm=login-loginForm"
    post = session.post(submit_url, data=payload)
    # Check for a successful login by looking for the logout link in the
    # response.  If the credentials are wrong, the login page will be
    # returned again without the logout marker.
    if post.status_code != 200 or "Odhlásit se" not in post.text:
        raise RuntimeError("Authentication failed; check your email/password.")


def prepare_upload(
    session: requests.Session,
    filename: str,
    size: int,
    mime_type: str,
    description: str = "",
    private: bool = False,
    erotic: bool = False,
    folder: str = "",
) -> Dict[str, Any]:
    """Initiate upload and return upload metadata.

    Sends metadata about the file to ``/profil/nahrat‑soubor?do=prepareVideo``.
    The server responds with a JSON document containing the fields required
    for the actual file transfer【346333217228061†L1515-L1533】.

    Args:
        session: Authenticated requests session.
        filename: Name of the file to upload.
        size: File size in bytes.
        mime_type: MIME type of the file.
        description: Optional textual description.
        private: Mark the video as private so that it is hidden from the
            public listing (corresponds to the “Všechny soubory jsou
            soukromé” checkbox on the web form【346333217228061†L600-L629】).
        erotic: Mark the video as erotic content (corresponds to the
            “Všechny soubory mají erotický obsah” checkbox).
        folder: ID of a folder on the account; an empty string selects
            the default folder.

    Returns:
        A dictionary with the keys ``project``, ``nonce``, ``params`` and
        ``signature`` which should be passed to :func:`upload_binary`.

    Raises:
        RuntimeError: If the prepare request does not return the expected
            JSON structure.
    """
    # Compose metadata.  Booleans are sent as lowercase strings to match
    # jQuery's behaviour on the original form.
    data = {
        "description": description,
        "name": filename,
        "size": size,
        "type": mime_type,
        "erotic": "true" if erotic else "false",
        "folder": folder,
        "private": "true" if private else "false",
    }
    url = "https://prehrajto.cz/profil/nahrat-soubor?do=prepareVideo"
    resp = session.post(url, data=data)
    try:
        info = resp.json()
    except Exception as exc:  # noqa: broad-except
        raise RuntimeError(f"Unexpected response from prepareVideo: {resp.text[:200]}") from exc
    required_keys = {"project", "nonce", "params", "signature"}
    if not required_keys.issubset(set(info.keys())):
        raise RuntimeError(f"Missing fields in prepareVideo response: {info}")
    return info


def upload_binary(
    session: requests.Session,
    metadata: Dict[str, Any],
    filename: str,
    size: int,
    mime_type: str,
    file_iter_factory: Callable[[int], Iterable[bytes]],
    show_progress: bool = False,
) -> Dict[str, Any]:
    """Transfer the binary data to the external CDN.

    Performs a multipart/form‑data POST to ``https://api.premiumcdn.net/upload/``
    with the file and the parameters returned by :func:`prepare_upload`.  The
    parameter ``response`` is set to ``JSON`` so that the API returns a
    machine‑parsable result【346333217228061†L1448-L1473】.  On success the server
    returns a JSON document describing the newly uploaded file.

    Args:
        session: Authenticated requests session.
        metadata: Dictionary containing ``project``, ``nonce``, ``params``
            and ``signature`` from the preparation step.
        filename: Name of the file being uploaded.
        size: File size in bytes.
        mime_type: MIME type of the file.
        file_iter_factory: Callable returning an iterator over file chunks.

    Returns:
        A dictionary parsed from the JSON response of the upload API.

    Raises:
        RuntimeError: If the upload fails or the server returns a non‑JSON
            response.
    """
    import threading
    import itertools
    import time

    class ProgressReporter:
        """Handles spinner → percent progress transitions."""

        def __init__(self, total_size: int) -> None:
            self.total_size = total_size
            self.start_time = time.monotonic()
            self.uploaded = 0
            self.percent_mode = False
            self._last_percent = -1
            self._min_bytes_before_percent = max(1, int(total_size * 0.05))
            self._spinner_stop = threading.Event()
            self._spinner_thread = threading.Thread(
                target=self._spinner, args=(self._spinner_stop,), daemon=True
            )
            self._spinner_thread.start()

        def _spinner(self, stop_event: threading.Event) -> None:
            """Display a simple spinner while progress is unknown."""
            for char in itertools.cycle("|/-\\"):
                if stop_event.is_set():
                    break
                sys.stderr.write(f"\rUploading... {char}")
                sys.stderr.flush()
                time.sleep(0.1)

        def _stop_spinner(self) -> None:
            if self._spinner_thread.is_alive():
                self._spinner_stop.set()
                self._spinner_thread.join()
                sys.stderr.write("\r")
                sys.stderr.flush()

        def _current_percent(self) -> int:
            if self.total_size == 0:
                return 100
            return int((self.uploaded / self.total_size) * 100)

        def _format_rate(self) -> str:
            elapsed = max(0.001, time.monotonic() - self.start_time)
            rate = self.uploaded / elapsed
            units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"]
            unit_index = 0
            while rate >= 1024 and unit_index < len(units) - 1:
                rate /= 1024
                unit_index += 1
            return f"{rate:.1f} {units[unit_index]}"

        def _maybe_switch_to_percent(self) -> None:
            if self.percent_mode:
                return
            elapsed = time.monotonic() - self.start_time
            if self.uploaded >= self._min_bytes_before_percent or elapsed >= 1.0:
                self.percent_mode = True
                self._stop_spinner()
                self._print_percent(force=True)

        def _print_percent(self, force: bool = False) -> None:
            percent = self._current_percent()
            if not force and percent == self._last_percent:
                return
            self._last_percent = percent
            rate = self._format_rate()
            sys.stderr.write(f"\rUploading... {percent}% ({rate})")
            sys.stderr.flush()

        def update(self, delta: int) -> None:
            self.uploaded += delta
            self._maybe_switch_to_percent()
            if self.percent_mode:
                self._print_percent()

        def finish(self) -> None:
            self._stop_spinner()
            if self.percent_mode:
                self._print_percent(force=True)
            sys.stderr.write("\n")
            sys.stderr.flush()

    reporter = ProgressReporter(size) if show_progress else None
    text_fields = {
        "response": "JSON",
        "project": metadata["project"],
        "nonce": metadata["nonce"],
        "params": metadata["params"],
        "signature": metadata["signature"],
    }
    boundary = f"----prehrajto-{os.urandom(8).hex()}"

    def _encode_field(name: str, value: str) -> bytes:
        return (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
        ).encode("utf-8") + value.encode("utf-8") + b"\r\n"

    file_header = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="files"; filename="{filename}"\r\n'
        f"Content-Type: {mime_type}\r\n\r\n"
    ).encode("utf-8")
    closing_boundary = f"--{boundary}--\r\n".encode("utf-8")

    class MultipartStream:
        """Iterable body with a stable length so requests sets Content-Length."""

        chunk_size = 64 * 1024

        def __iter__(self):
            for key, value in text_fields.items():
                yield _encode_field(key, value)
            yield file_header
            for data_chunk in file_iter_factory(self.chunk_size):
                if not data_chunk:
                    continue
                if reporter:
                    reporter.update(len(data_chunk))
                yield data_chunk
            yield b"\r\n"
            yield closing_boundary

        def __len__(self) -> int:
            length = sum(len(_encode_field(k, v)) for k, v in text_fields.items())
            length += len(file_header) + size + len(b"\r\n")
            length += len(closing_boundary)
            return length

    body = MultipartStream()

    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    }

    try:
        resp = session.post(
            "https://api.premiumcdn.net/upload/",
            data=body,
            headers=headers,
        )
    finally:
        if reporter:
            reporter.finish()
    try:
        return resp.json()
    except Exception as exc:  # noqa: broad-except
        raise RuntimeError(f"Upload failed: {resp.text[:200]}") from exc


def _split_content_type(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    return value.split(";", 1)[0].strip() or None


def _extract_filename(content_disposition: Optional[str]) -> Optional[str]:
    if not content_disposition:
        return None
    parts = [part.strip() for part in content_disposition.split(";")]
    for part in parts[1:]:
        if part.startswith("filename*="):
            value = part.split("=", 1)[1].strip()
            if "''" in value:
                value = value.split("''", 1)[1]
                value = urllib.parse.unquote(value)
            return value.strip('"') or None
        if part.startswith("filename="):
            value = part.split("=", 1)[1].strip()
            return value.strip('"') or None
    return None


def _filename_from_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    name = os.path.basename(parsed.path)
    return name or "download.bin"


def _guess_mime_type(name: str, header_type: Optional[str]) -> str:
    header = _split_content_type(header_type)
    if header:
        return header
    mime_type, _ = mimetypes.guess_type(name)
    return mime_type or "application/octet-stream"


def _remote_head(
    session: requests.Session,
    url: str,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    headers = {"Accept-Encoding": "identity"}
    resp = session.head(url, allow_redirects=True, headers=headers)
    try:
        if resp.status_code >= 400:
            return None, None, None
        return (
            resp.headers.get("Content-Length"),
            resp.headers.get("Content-Type"),
            resp.headers.get("Content-Disposition"),
        )
    finally:
        resp.close()


def _remote_get_headers(
    session: requests.Session,
    url: str,
) -> Tuple[str, Optional[str], Optional[str]]:
    headers = {"Accept-Encoding": "identity"}
    resp = session.get(url, allow_redirects=True, stream=True, headers=headers)
    try:
        if resp.status_code >= 400:
            raise RuntimeError(f"Failed to access remote file (status {resp.status_code}).")
        return (
            resp.headers.get("Content-Length"),
            resp.headers.get("Content-Type"),
            resp.headers.get("Content-Disposition"),
        )
    finally:
        resp.close()


def get_remote_file_info(
    session: requests.Session,
    url: str,
    filename_override: Optional[str] = None,
) -> Tuple[str, int, str]:
    size_header, content_type, content_disp = _remote_head(session, url)
    if not size_header:
        size_header, content_type, content_disp = _remote_get_headers(session, url)
    if not size_header:
        raise RuntimeError("Remote file does not provide Content-Length.")
    try:
        size = int(size_header)
    except ValueError as exc:
        raise RuntimeError(f"Invalid Content-Length: {size_header}") from exc
    filename = filename_override or _extract_filename(content_disp) or _filename_from_url(url)
    mime_type = _guess_mime_type(filename, content_type)
    return filename, size, mime_type


def iter_local_file(file_path: str, chunk_size: int) -> Iterable[bytes]:
    with open(file_path, "rb") as fh:
        while True:
            data_chunk = fh.read(chunk_size)
            if not data_chunk:
                break
            yield data_chunk


def iter_remote_file(session: requests.Session, url: str, chunk_size: int) -> Iterable[bytes]:
    headers = {"Accept-Encoding": "identity"}
    resp = session.get(url, allow_redirects=True, stream=True, headers=headers)
    resp.raise_for_status()
    try:
        for data_chunk in resp.iter_content(chunk_size=chunk_size):
            if data_chunk:
                yield data_chunk
    finally:
        resp.close()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Upload a file to Prehraj.to via the command line",
        epilog=(
            "This script performs the same two‑step upload process as the web "
            "interface.  It logs in, prepares the upload and streams the file "
            "to the CDN.  Upon success it prints the JSON response returned "
            "by the server."
        ),
    )
    parser.add_argument("--email", required=True, help="Přehráj.to account email")
    parser.add_argument("--password", required=True, help="Přehráj.to account password")
    file_group = parser.add_mutually_exclusive_group(required=True)
    file_group.add_argument("--file", dest="file_path", help="Path to the file to upload")
    file_group.add_argument(
        "--remote-url",
        dest="remote_url",
        help="HTTP(S) URL of a remote file to stream-upload",
    )
    parser.add_argument(
        "--remote-filename",
        dest="remote_filename",
        default=None,
        help="Override the filename for remote uploads",
    )
    parser.add_argument(
        "--description",
        default="",
        help="Optional description for the uploaded file (default: empty)",
    )
    parser.add_argument(
        "--private",
        action="store_true",
        help="Mark the uploaded file as private (hidden from public listings)",
    )
    parser.add_argument(
        "--erotic",
        action="store_true",
        help="Mark the uploaded file as erotic content",
    )
    parser.add_argument(
        "--folder",
        default="",
        help=(
            "Identifier of a folder to upload into.  Use an empty string for "
            "the default folder.  At the time of writing the upload page only "
            "exposes the default folder option【346333217228061†L600-L629】."
        ),
    )

    args = parser.parse_args(argv)

    if args.file_path and not os.path.isfile(args.file_path):
        print(f"The file '{args.file_path}' does not exist or is not a regular file.", file=sys.stderr)
        return 1

    session = requests.Session()
    try:
        login(session, args.email, args.password)
        if args.file_path:
            filename = os.path.basename(args.file_path)
            size = os.path.getsize(args.file_path)
            mime_type, _ = mimetypes.guess_type(args.file_path)
            if not mime_type:
                mime_type = "application/octet-stream"
            file_iter_factory = lambda chunk_size: iter_local_file(args.file_path, chunk_size)
        else:
            filename, size, mime_type = get_remote_file_info(
                session,
                args.remote_url,
                filename_override=args.remote_filename,
            )
            file_iter_factory = lambda chunk_size: iter_remote_file(session, args.remote_url, chunk_size)
        meta = prepare_upload(
            session,
            filename,
            size,
            mime_type,
            description=args.description,
            private=args.private,
            erotic=args.erotic,
            folder=args.folder,
        )
        result = upload_binary(
            session,
            meta,
            filename,
            size,
            mime_type,
            file_iter_factory,
            show_progress=True,
        )
        # Print the JSON response in a human‑readable format.
        import json as _json  # local import to avoid polluting global namespace
        print(_json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv[1:]))
