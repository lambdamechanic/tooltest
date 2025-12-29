# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM debian:bookworm-slim AS base

ARG DEBIAN_FRONTEND=noninteractive
ARG RUST_VERSION=1.91.0
ARG BD_VERSION=v0.23.1
ARG USERNAME=agent
ARG USER_UID=1000
ARG USER_GID=1000

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    RUSTUP_HOME=/opt/rust/rustup \
    CARGO_HOME=/opt/rust/cargo \
    PATH=/opt/rust/cargo/bin:/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin \
    CARGO_NET_GIT_FETCH_WITH_CLI=true

# Add GitHub CLI apt repository once so every agent image can rely on `gh`.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
    && install -d -m 0755 /etc/apt/keyrings \
    && curl --retry 5 -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
        -o /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
        > /etc/apt/sources.list.d/github-cli.list \
    && rm -rf /var/lib/apt/lists/*

# System packages shared by every agent runtime.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash-completion \
        build-essential \
        cmake \
        file \
        g++ \
        gdb \
        git \
        jq \
        less \
        libsqlite3-dev \
        libssl-dev \
        lsb-release \
        pkg-config \
        python3 \
        python3-dev \
        python3-pip \
        python3-venv \
        ripgrep \
        rsync \
        sudo \
        tmux \
        unzip \
        wget \
        zip \
        zsh \
        fd-find \
        openssh-client \
        gh \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/fdfind /usr/local/bin/fd

# Install Rust toolchain + common components once in the base image.
RUN curl --retry 5 -fsSL https://sh.rustup.rs | sh -s -- -y --default-toolchain ${RUST_VERSION} --profile minimal \
    && rustup component add clippy rustfmt llvm-tools-preview \
    && cargo install cargo-llvm-cov --locked

# Install bd CLI from the pinned release (amd64) or compile from source (arm64).
RUN ARCH="$(dpkg --print-architecture)" \
    && if [ "$ARCH" = "amd64" ]; then \
        BD_ARCHIVE="beads_${BD_VERSION#v}_linux_amd64.tar.gz" \
        && BD_SHA="ae44a2fec58283ef1b9f13009fd24d7133e8fd7ca9651d3d1bf880c5d782c433" \
        && curl --retry 5 -fsSL "https://github.com/steveyegge/beads/releases/download/${BD_VERSION}/${BD_ARCHIVE}" -o /tmp/bd.tar.gz \
        && echo "${BD_SHA}  /tmp/bd.tar.gz" | sha256sum --check - \
        && tar -xzf /tmp/bd.tar.gz -C /usr/local/bin bd \
        && chmod +x /usr/local/bin/bd \
        && rm -f /tmp/bd.tar.gz; \
    elif [ "$ARCH" = "arm64" ]; then \
        apt-get update \
        && apt-get install -y --no-install-recommends golang \
        && rm -rf /var/lib/apt/lists/* \
        && GOBIN=/usr/local/bin GO111MODULE=on go install github.com/steveyegge/beads/cmd/bd@${BD_VERSION} \
        && strip /usr/local/bin/bd || true; \
    else \
        echo "Unsupported architecture: $ARCH" >&2; exit 1; \
    fi

# Create the non-root user that agents attach to.
RUN groupadd --gid ${USER_GID} ${USERNAME} \
    && useradd --uid ${USER_UID} --gid ${USER_GID} --create-home --shell /bin/bash ${USERNAME} \
    && mkdir -p ${RUSTUP_HOME} ${CARGO_HOME} \
    && chown -R ${USERNAME}:${USERNAME} ${RUSTUP_HOME} ${CARGO_HOME} \
    && echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USERNAME} \
    && chmod 0440 /etc/sudoers.d/${USERNAME}

WORKDIR /workspace
USER ${USERNAME}

CMD ["/bin/bash"]
