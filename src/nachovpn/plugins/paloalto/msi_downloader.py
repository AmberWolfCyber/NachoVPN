import xml.etree.ElementTree as ET
import argparse
import requests
import sys
import os

class MSIDownloader:
    def __init__(self, output_dir):
        self.xml_url = "https://pan-gp-client.s3.amazonaws.com"
        self.x86_msi = "GlobalProtect.msi"
        self.x64_msi = "GlobalProtect64.msi"
        self.output_dir = output_dir

    def get_latest_versions(self):
        response = requests.get(self.xml_url)
        response.raise_for_status()

        root = ET.fromstring(response.content)
        ns = {'s3': 'http://s3.amazonaws.com/doc/2006-03-01/'}

        contents = root.findall('.//s3:Contents', ns)
        x86_keys = [c.find('s3:Key', ns).text for c in contents if 'GlobalProtect.msi' in c.find('s3:Key', ns).text]
        x64_keys = [c.find('s3:Key', ns).text for c in contents if 'GlobalProtect64.msi' in c.find('s3:Key', ns).text]

        latest_version_x86 = sorted(x86_keys)[-1]
        latest_version_x64 = sorted(x64_keys)[-1]

        return latest_version_x86, latest_version_x64

    def download_file(self, url, output_path):
        print(f"Downloading file from: {url}")
        response = requests.get(url, stream=True)
        response.raise_for_status()

        total_size = int(response.headers.get('content-length', 0))
        block_size = 1024
        current_size = 0

        with open(output_path, 'wb') as f:
            for data in response.iter_content(block_size):
                current_size += len(data)
                f.write(data)

                # Calculate progress
                if total_size:
                    progress = int(50 * current_size / total_size)
                    sys.stdout.write(f"\rDownloading: [{'=' * progress}{' ' * (50-progress)}] {current_size}/{total_size} bytes")
                    sys.stdout.flush()

        # New line after progress bar
        print()

    def download_latest_msi(self):
        latest_version_x86, latest_version_x64 = self.get_latest_versions()

        x86_url = f"{self.xml_url}/{latest_version_x86}"
        x64_url = f"{self.xml_url}/{latest_version_x64}"

        print(f"Downloading latest MSI files (version: {latest_version_x86.split('/')[0]})")

        # Download both MSI files
        os.makedirs(self.output_dir, exist_ok=True)
        x86_path = os.path.join(self.output_dir, self.x86_msi)
        x64_path = os.path.join(self.output_dir, self.x64_msi)

        print(f"Downloading: {self.x86_msi}")
        self.download_file(x86_url, x86_path)

        print(f"Downloading: {self.x64_msi}")
        self.download_file(x64_url, x64_path)

        # Verify downloads
        if not os.path.getsize(x86_path) or not os.path.getsize(x64_path):
            raise Exception("Failed to download MSI files")

        print(f"Successfully downloaded {self.x86_msi} and {self.x64_msi}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Download GlobalProtect MSI files')
    parser.add_argument('-o', '--output-dir', default=os.path.join(os.getcwd(), 'downloads'),
                        help='Directory to store downloaded MSI files. Defaults to ./downloads/')
    parser.add_argument('-f', '--force', action='store_true', help='Force download even if files exist')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-d', '--download', action='store_true', help='Download latest MSI files')
    group.add_argument('-v', '--version', action='store_true', help='Show latest version information only')
    args = parser.parse_args()

    downloader = MSIDownloader(output_dir=args.output_dir)

    if args.version:
        x86_version, x64_version = downloader.get_latest_versions()
        print(f"Latest x86 version: {x86_version.split('/')[0]}")
        print(f"Latest x64 version: {x64_version.split('/')[0]}")

    # Check if MSI files exist or if force download is enabled
    elif args.download and (not os.path.exists(os.path.join(args.output_dir, "GlobalProtect.msi")) or \
       not os.path.exists(os.path.join(args.output_dir, "GlobalProtect64.msi")) or args.force):
        x86_version, x64_version = downloader.get_latest_versions()
        downloader.download_latest_msi()
        with open(os.path.join(args.output_dir, "msi_version.txt"), "w") as f:
            f.write(x64_version.split('/')[0])

    else:
        parser.print_help()
