# Vendored xslt-polyfill

Upstream: https://github.com/mfreed7/xslt_polyfill

- Version: 1.0.29
- Revision: `b2dff6401ba4b5f1b40bfd9f585c40f1130fea4c`
- `xslt-polyfill.min.js` SHA-256: `ff6517256893dbaedaaece103111cdf08586bc0133518e9c1090a0be60afc362`
- JavaScript source and bundle are unmodified upstream files.
- The bundle contains the libxml2/libxslt WebAssembly engine; there is no runtime CDN or separate Wasm download.
- Preserve LICENSE, COPYRIGHT, libxml2-COPYRIGHT and libxslt-COPYRIGHT when distributing.
- libxml2 revision: `c34742f3017f6d39f3e4ccae4f70172238160ef8`.
- libxslt revision: `923903c59d668af42e3144bc623c9190a0f65988`.

Update by fetching a pinned upstream revision, retaining its license notices,
updating this checksum, and running `tests/xslt-browser.cjs`. Do not substitute a
moving CDN URL. XOver's loader is in `../xslt.js`, outside the upstream bundle.
