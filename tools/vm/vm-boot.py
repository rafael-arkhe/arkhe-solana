#!/usr/bin/env python3
"""
vm-boot.py — Boot test para ArkheOS.

Instala uma imagem OCI bootc num disco virtual com composefs backend,
arranca em QEMU com KVM e UEFI, e verifica se o sistema atinge multi-user.target.

Uso:
    ./vm-boot.py --oci /tmp/arkhe-os.oci --disk /tmp/arkhe-os.qcow2

Baseado no script do NyraOS (tools/vm/vm-boot.py).
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def run(cmd, **kwargs):
    """Executa comando e falha em erro."""
    result = subprocess.run(cmd, capture_output=True, text=True, **kwargs)
    if result.returncode != 0:
        print(f"FALHA: {' '.join(cmd)}", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(result.returncode)
    return result


def install_to_disk(oci: Path, disk: Path):
    """Instala a imagem OCI no disco com composefs backend."""
    if disk.exists():
        disk.unlink()

    # Cria disco qcow2 de 4 GiB
    run([
        "qemu-img", "create", "-f", "qcow2",
        str(disk), "4G"
    ])

    # Instala via bootc (requer root)
    run([
        "sudo", "bootc", "install", "to-disk",
        "--composefs-backend",
        "--bootloader", "systemd",
        "--filesystem", "ext4",
        "--target", str(disk),
        f"oci-archive:{oci}",
    ])


def boot_qemu(disk: Path, log_path: Path, timeout: int = 300):
    """Arranca QEMU com KVM e UEFI, captura serial para log."""
    # Localiza OVMF
    ovmf_candidates = [
        "/usr/share/OVMF/OVMF_CODE.fd",
        "/usr/share/edk2/ovmf/OVMF_CODE.fd",
    ]
    ovmf = next((p for p in ovmf_candidates if os.path.exists(p)), None)
    if not ovmf:
        print("ERRO: OVMF não encontrado", file=sys.stderr)
        sys.exit(1)

    cmd = [
        "qemu-system-x86_64",
        "-enable-kvm",
        "-m", "2048",
        "-cpu", "host",
        "-drive", f"if=virtio,file={disk},format=qcow2",
        "-bios", ovmf,
        "-nographic",
        "-serial", "mon:stdio",
        "-no-reboot",
    ]

    print(f"Arrancando QEMU (timeout {timeout}s)...")
    with open(log_path, "w") as log:
        proc = subprocess.Popen(
            cmd,
            stdout=log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            print(f"Timeout após {timeout}s")


def check_boot(log_path: Path) -> bool:
    """Verifica se o sistema atingiu multi-user.target."""
    content = log_path.read_text(errors="ignore")
    if "Reached target Multi-User System" in content:
        print("PASS: sistema atingiu multi-user.target")
        return True

    # Fallback: procura login prompt
    if "login:" in content or "getty" in content:
        print("PASS: login prompt encontrado (multi-user implícito)")
        return True

    print("FAIL: sistema não atingiu multi-user.target", file=sys.stderr)
    print("Últimas 50 linhas do log:", file=sys.stderr)
    print("\n".join(content.splitlines()[-50:]), file=sys.stderr)
    return False


def main():
    parser = argparse.ArgumentParser(description="Boot test para ArkheOS")
    parser.add_argument("--oci", type=Path, required=True, help="Caminho para o oci-archive")
    parser.add_argument("--disk", type=Path, default=Path("/tmp/arkhe-os.qcow2"),
                        help="Caminho para o disco qcow2")
    parser.add_argument("--log", type=Path, default=Path("/tmp/arkhe-os-boot.log"),
                        help="Caminho para o log de boot")
    parser.add_argument("--timeout", type=int, default=300, help="Timeout de boot (s)")
    args = parser.parse_args()

    if not args.oci.exists():
        print(f"ERRO: {args.oci} não existe", file=sys.stderr)
        sys.exit(1)

    install_to_disk(args.oci, args.disk)
    boot_qemu(args.disk, args.log, args.timeout)

    if check_boot(args.log):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
