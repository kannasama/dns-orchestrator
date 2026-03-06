# ── Stage 1: UI build ───────────────────────────────────────────────────────
FROM node:22-slim AS ui-builder

WORKDIR /ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci
COPY ui/ .
RUN npm run build

# ── Stage 2: C++ build ─────────────────────────────────────────────────────
FROM fedora:43 AS builder

RUN dnf install -y --setopt=install_weak_deps=False \
  cmake ninja-build gcc-c++ \
  libpqxx-devel openssl-devel libgit2-devel \
  json-devel spdlog-devel \
  asio-devel \
  pkgconf-pkg-config \
  git ca-certificates \
  && dnf clean all

WORKDIR /build
COPY . .

RUN cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_UI=OFF \
  && cmake --build build --parallel

# ── Stage 3: Runtime ───────────────────────────────────────────────────────
FROM fedora:43 AS runtime

RUN dnf install -y --setopt=install_weak_deps=False \
  libpq libpqxx openssl-libs libgit2 spdlog fmt \
  && dnf clean all

RUN useradd --system --no-create-home meridian-dns

COPY --from=builder /build/build/src/meridian-dns /usr/local/bin/meridian-dns
COPY --from=ui-builder /ui/dist /opt/meridian-dns/ui
COPY scripts/db/ /opt/meridian-dns/db/
COPY scripts/docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV DNS_UI_DIR=/opt/meridian-dns/ui

USER meridian-dns
EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
CMD ["meridian-dns"]
