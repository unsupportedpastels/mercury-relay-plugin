# Vendored dependencies

`noise/` is `noiseprotocol==0.3.1` (MIT, pure Python), vendored verbatim so the
plugin installs zero-click: Hermes never auto-installs plugin Python
dependencies, and the only other requirement (`cryptography`) ships with
Hermes itself. `secure_channel` adds this directory to `sys.path` only when no
site installation of `noise` exists; an installed copy always wins.

`segno/` is `segno==1.6.6` (BSD, pure Python), vendored for server-side QR SVG
generation so both the dashboard page and the desktop plugin render one
identical QR without shipping a client-side QR library. `pairing` imports it
through the same site-installation-wins fallback.

Do not modify the vendored sources. To upgrade, replace the `noise/` or
`segno/` tree with the new pinned release and rerun the relevant test suite.
