#!/usr/bin/env bash

set -Eeuo pipefail

go_version="1.26.7"

case "$(uname -m)" in
    x86_64)
        go_arch="amd64"
        go_checksum="ffb5f8de10c62550dfddab66b36b57030721e0a44a3218e9e1181d7b59f121ca"
        ;;
    aarch64 | arm64)
        go_arch="arm64"
        go_checksum="5a4ec883379d51ee9ce1040d5e87f8d35e20387574dd8c947feb01eabc3c1b37"
        ;;
    *)
        echo "Unsupported architecture: $(uname -m)" >&2
        exit 1
        ;;
esac

for required_tool in curl grep mktemp sha256sum tar; do
    if ! command -v "$required_tool" >/dev/null 2>&1; then
        echo "Missing required tool: $required_tool" >&2
        exit 1
    fi
done

if (( EUID == 0 )); then
    root_command=()
else
    if ! command -v sudo >/dev/null 2>&1; then
        echo "sudo is required to install Go under /usr/local" >&2
        exit 1
    fi
    root_command=(sudo)
    "${root_command[@]}" -v
fi

task_tmp_dir="$(mktemp -d)"
cleanup() {
    rm -rf -- "${task_tmp_dir:?}"
}
trap cleanup EXIT

rust_cargo_dir="${CARGO_HOME:-${HOME}/.cargo}"
if [[ -f "$rust_cargo_dir/env" ]]; then
    # shellcheck disable=SC1090
    source "$rust_cargo_dir/env"
fi

if command -v rustup >/dev/null 2>&1; then
    rustup update stable
    rustup default stable
else
    rustup_installer="$task_tmp_dir/rustup-init.sh"
    curl --proto '=https' --tlsv1.2 --fail --show-error --location \
        https://sh.rustup.rs -o "$rustup_installer"
    sh "$rustup_installer" -y --profile minimal --default-toolchain stable --no-modify-path
    export PATH="$rust_cargo_dir/bin:$PATH"
fi
rustup component add rustfmt clippy

go_archive_name="go${go_version}.linux-${go_arch}.tar.gz"
go_install_dir="/usr/local/go-${go_version}"

if [[ ! -x "$go_install_dir/bin/go" ]]; then
    if [[ -e "$go_install_dir" ]]; then
        echo "$go_install_dir exists but is not a complete Go installation" >&2
        exit 1
    fi

    go_archive="$task_tmp_dir/$go_archive_name"
    curl --proto '=https' --tlsv1.2 --fail --show-error --location \
        "https://go.dev/dl/$go_archive_name" -o "$go_archive"
    printf '%s  %s\n' "$go_checksum" "$go_archive" | sha256sum -c -
    tar -C "$task_tmp_dir" -xzf "$go_archive"
    "${root_command[@]}" mv "$task_tmp_dir/go" "$go_install_dir"
fi

if [[ -e /usr/local/go && ! -L /usr/local/go ]]; then
    echo "/usr/local/go already exists and is not a symlink; refusing to replace it" >&2
    exit 1
fi
"${root_command[@]}" ln -sfnT "$go_install_dir" /usr/local/go

zsh_profile="${ZDOTDIR:-${HOME}}/.zshrc"
path_setting='export PATH="$HOME/.cargo/bin:/usr/local/go/bin:$PATH"'
if [[ ! -f "$zsh_profile" ]] || ! grep -Fqx "$path_setting" "$zsh_profile"; then
    printf '\n%s\n' "$path_setting" >> "$zsh_profile"
fi

export PATH="$rust_cargo_dir/bin:/usr/local/go/bin:$PATH"

rustc --version
cargo --version
go version
echo "Rust and Go are installed. Restart the shell or run: source $zsh_profile"
