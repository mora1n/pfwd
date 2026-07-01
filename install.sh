#!/bin/sh
set -eu

repo="mora1n/pfwd"
install_path="/usr/local/bin/pfwd"

die() {
	printf '错误：%s\n' "$*" >&2
	exit 1
}

if [ "$(id -u)" != "0" ]; then
	die "请以 root 用户运行"
fi

if ! command -v curl >/dev/null 2>&1; then
	die "缺少 curl"
fi

case "$(uname -m)" in
	x86_64|amd64)
		arch="amd64"
		;;
	aarch64|arm64)
		arch="arm64"
		;;
	*)
		die "不支持的架构：$(uname -m)"
		;;
esac

url="https://github.com/$repo/releases/latest/download/pfwd-linux-$arch"
tmp="$install_path.tmp.$$"

trap 'rm -f "$tmp"' EXIT HUP INT TERM

mkdir -p "$(dirname "$install_path")"
curl -fsSL "$url" -o "$tmp"
chmod 755 "$tmp"
mv "$tmp" "$install_path"

"$install_path" install
