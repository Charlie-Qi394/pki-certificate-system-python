from setuptools import find_packages, setup


setup(
    name="pki-certificate-system",
    version="0.1.0",
    description="Educational PKI certificate system using RSA, AES, X.509 certificates, CSRs, and CRLs.",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=["cryptography>=42.0.0"],
    extras_require={"dev": ["pytest>=8.0.0"]},
    python_requires=">=3.9",
)
