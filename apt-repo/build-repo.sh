#!/bin/sh
# Builds a signed flat apt repository of the .deb files in the working directory, signed with the
# key of the build secret gpg_key, unlocked with the passphrase of gpg_passphrase when it is given.
set -eu

export GNUPGHOME=/tmp/gnupg
mkdir -m 700 "$GNUPGHOME"
set -- --batch --yes
if [ -f /run/secrets/gpg_passphrase ]; then
    set -- "$@" --pinentry-mode loopback --passphrase-file /run/secrets/gpg_passphrase
fi
gpg "$@" --import /run/secrets/gpg_key

apt-ftparchive packages . > Packages
gzip -9 -k Packages
apt-ftparchive -o APT::FTPArchive::Release::Origin=simple-ca -o APT::FTPArchive::Release::Label=simple-ca \
    release . > /tmp/Release
mv /tmp/Release Release
gpg "$@" --clearsign -o InRelease Release
gpg "$@" --armor --detach-sign -o Release.gpg Release
gpg --armor --export > key.asc
