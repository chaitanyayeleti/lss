pkgname=lss
pkgver=0.1.0
pkgrel=1
pkgdesc="Local Secret Scanner"
arch=('x86_64')
url="https://github.com/chaitanyayeleti/lss"
license=('MIT')
depends=('libgit2' 'libssh2' 'openssl')
makedepends=('cargo' 'rust' 'pkg-config' 'libgit2' 'openssl' 'libssh2')
source=("https://github.com/chaitanyayeleti/lss/archive/refs/tags/v${pkgver}.tar.gz")
sha256sums=('SKIP')

build() {
  cd "${srcdir}/lss-${pkgver}"
  # Use a locked build for reproducibility
  cargo build --release --locked
}

package() {
  cd "${srcdir}/lss-${pkgver}"
  install -Dm755 "target/release/lss" "${pkgdir}/usr/bin/lss"
  install -Dm644 README.md "${pkgdir}/usr/share/doc/${pkgname}/README.md"
  if [ -f LICENSE ]; then
    install -Dm644 LICENSE "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"
  fi
}
