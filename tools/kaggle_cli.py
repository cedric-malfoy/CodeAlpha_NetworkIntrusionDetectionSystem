"""Official Kaggle CLI with OAuth storage following KAGGLE_CONFIG_DIR.

Kaggle 2.2.5 honors that variable for API settings but its SDK still defaults
OAuth credentials to ~/.kaggle. Keep credentials outside the source checkout.
"""
import os
import sys
from pathlib import Path


def main():
    location = Path(os.environ.get("KAGGLE_CONFIG_DIR", "/tmp/codealpha-kaggle"))
    location.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.environ["KAGGLE_CONFIG_DIR"] = str(location)
    token_file = location / "access_token"
    if token_file.exists() and "KAGGLE_API_TOKEN" not in os.environ:
        os.environ["KAGGLE_API_TOKEN"] = token_file.read_text().strip()
    from kagglesdk.kaggle_creds import KaggleCredentials
    credentials = str(location / "credentials.json")
    KaggleCredentials.DEFAULT_CREDENTIALS_FILE = credentials
    KaggleCredentials.save.__defaults__ = (credentials,)
    KaggleCredentials.delete.__defaults__ = (credentials,)
    if sys.argv[1:3] == ["auth", "login"]:
        # CLI 2.2.5 authenticates before dispatching even its login subcommand.
        # Invoke its official SDK login flow directly to bootstrap credentials.
        from kagglesdk.kaggle_client import KaggleClient
        from kagglesdk.kaggle_oauth import KaggleOAuth
        with KaggleClient() as client:
            KaggleOAuth(client).authenticate(["resources.admin:*"], no_launch_browser=True)
        return
    from kaggle.cli import main as kaggle_main
    kaggle_main()


if __name__ == "__main__":
    main()
