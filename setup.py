from setuptools import setup, find_packages

setup(
    name="nachovpn",
    version="1.0.0",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    include_package_data=True,
    install_requires=[
        "cryptography==42.0.5",
        "jinja2>=3.0.0",
        "scapy>=2.5.0",
        "requests>=2.31.0",
        "flask>=3.0.2",
        "cabarchive>=0.2.4",
        "pycryptodome>=3.20.0",
        "PyJWT>=2.10.1",
        "pyroute2>=0.9.2",
    ],
    python_requires=">=3.9",
    description="A delicious, but malicious SSL-VPN server",
    entry_points={
        "console_scripts": [
            "nachovpn=nachovpn.server:main",
        ],
    },
)
