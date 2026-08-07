#!/usr/bin/env python3
"""Patch Tauri v1's generated NSIS installer with a data-aware upgrade guard.

Tauri v1 renders the complete NSIS script immediately before compiling it.  This
helper deliberately patches that generated script instead of maintaining a
large fork of Tauri's installer template.  It then optionally recompiles the
installer and replaces Tauri's bundle artifact.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

PATCH_MARKER = "; SPORE_DATA_GUARD_BEGIN"

DATA_GUARD_BLOCK = r'''
; SPORE_DATA_GUARD_BEGIN
; Spore keeps runtime data in the installation directory.  Before Tauri's
; normal reinstall page can uninstall the old version, detect those files and
; let the user explicitly choose whether the existing configuration is kept.
Var SporePreserveExistingData
Var SporeExistingDataFound
Var SporeExistingInstallDir
Var SporeDataKeepRadio
Var SporeDataOverwriteRadio

Page custom SporeExistingDataPage SporeExistingDataPageLeave

Function SporeResolveExistingInstallDir
  StrCpy $SporeExistingInstallDir ""

  ; Tauri stores the unquoted installation path here for future upgrades.
  ReadRegStr $SporeExistingInstallDir SHCTX "${MANUPRODUCTKEY}" ""

  ; Fall back to Add/Remove Programs metadata when upgrading an older build.
  ${If} $SporeExistingInstallDir == ""
    ReadRegStr $SporeExistingInstallDir SHCTX "${UNINSTKEY}" "InstallLocation"
  ${EndIf}

  ; InstallLocation is quoted by Tauri; strip the surrounding quotes.
  StrCpy $0 $SporeExistingInstallDir 1
  ${If} $0 == '"'
    StrCpy $SporeExistingInstallDir $SporeExistingInstallDir "" 1
  ${EndIf}
  StrCpy $0 $SporeExistingInstallDir 1 -1
  ${If} $0 == '"'
    StrCpy $SporeExistingInstallDir $SporeExistingInstallDir -1
  ${EndIf}

  ; Last chance for non-registered/portable-style previous installations.
  ${If} $SporeExistingInstallDir == ""
  ${AndIf} ${FileExists} "$INSTDIR\${MAINBINARYNAME}.exe"
    StrCpy $SporeExistingInstallDir $INSTDIR
  ${EndIf}
FunctionEnd

Function SporeDetectExistingData
  StrCpy $SporeExistingDataFound 0
  Call SporeResolveExistingInstallDir

  ${If} $SporeExistingInstallDir == ""
    Return
  ${EndIf}

  ; Configuration and user-created runtime data. Prompt/characters are
  ; application resources that are updated by a new release. The entire skills
  ; directory is treated as user-maintained data in the safe upgrade path.
  IfFileExists "$SporeExistingInstallDir\.env" spore_data_found 0
  IfFileExists "$SporeExistingInstallDir\note.txt" spore_data_found 0
  IfFileExists "$SporeExistingInstallDir\.spore_config_profiles.json" spore_data_found 0
  IfFileExists "$SporeExistingInstallDir\tool_policy.json" spore_data_found 0
  IfFileExists "$SporeExistingInstallDir\skills\*" spore_data_found 0
  IfFileExists "$SporeExistingInstallDir\.spore\*" spore_data_found 0
  IfFileExists "$SporeExistingInstallDir\output\*" spore_data_found 0
  IfFileExists "$SporeExistingInstallDir\history\*" spore_data_found 0
  IfFileExists "$SporeExistingInstallDir\logs\*" spore_data_found 0
  Return

  spore_data_found:
    StrCpy $SporeExistingDataFound 1
FunctionEnd

Function SporeExistingDataPage
  Call SporeDetectExistingData
  ${If} $SporeExistingDataFound != 1
    StrCpy $SporePreserveExistingData 0
    Abort
  ${EndIf}

  ; Silent/passive upgrades default to the safe in-place path.
  ${If} $SporePreserveExistingData == ""
    StrCpy $SporePreserveExistingData 1
  ${EndIf}
  ${If} $SporePreserveExistingData == 1
    StrCpy $INSTDIR $SporeExistingInstallDir
  ${EndIf}
  Call SkipIfPassive

  !insertmacro MUI_HEADER_TEXT "Existing Spore data detected" "Choose how this upgrade handles the current installation"
  nsDialogs::Create 1018
  Pop $0
  ${IfThen} $(^RTL) == 1 ${|} nsDialogs::SetRTL $(^RTL) ${|}

  ${NSD_CreateLabel} 0 0 100% 28u "Existing configuration or runtime data was found at:$\r$\n$SporeExistingInstallDir"
  Pop $0

  ${NSD_CreateLabel} 0 34u 100% 26u "检测到已有 Spore 配置/数据。请选择覆盖安装方式："
  Pop $0

  ${NSD_CreateRadioButton} 10u 68u -10u 18u "Keep existing data and update application files (recommended) / 保留数据并更新程序"
  Pop $SporeDataKeepRadio

  ${NSD_CreateRadioButton} 10u 94u -10u 18u "Use the installer's normal overwrite/uninstall flow / 按默认流程覆盖或卸载旧版本"
  Pop $SporeDataOverwriteRadio

  ${NSD_CreateLabel} 10u 121u -10u 38u "Keeping data preserves .env, skills, note.txt, output, history, logs and .spore. Other program resources are still updated."
  Pop $0

  ${If} $SporePreserveExistingData == 1
    ${NSD_Check} $SporeDataKeepRadio
  ${Else}
    ${NSD_Check} $SporeDataOverwriteRadio
  ${EndIf}

  nsDialogs::Show
FunctionEnd

Function SporeExistingDataPageLeave
  ${NSD_GetState} $SporeDataKeepRadio $0
  ${If} $0 == ${BST_CHECKED}
    StrCpy $SporePreserveExistingData 1
    StrCpy $INSTDIR $SporeExistingInstallDir
    Return
  ${EndIf}

  MessageBox MB_ICONEXCLAMATION|MB_YESNO|MB_DEFBUTTON2 \
    "The normal overwrite flow may replace .env and may uninstall packaged files first.$\r$\n$\r$\nContinue without data protection?$\r$\n不保留配置保护，确认继续吗？" \
    IDYES spore_overwrite_confirmed IDNO spore_keep_data

  spore_keep_data:
    ${NSD_Check} $SporeDataKeepRadio
    ${NSD_Uncheck} $SporeDataOverwriteRadio
    StrCpy $SporePreserveExistingData 1
    Abort

  spore_overwrite_confirmed:
    StrCpy $SporePreserveExistingData 0
FunctionEnd
; SPORE_DATA_GUARD_END
'''.strip()

REINSTALL_SKIP_BLOCK = r'''
  ; SPORE_DATA_GUARD_REINSTALL_SKIP
  ; The safe choice is an in-place update: do not invoke the old uninstaller,
  ; because Tauri v1's generated uninstaller deletes the bundled .env file.
  ${If} $SporePreserveExistingData == 1
    Abort
  ${EndIf}
'''.rstrip()

ENV_FILE_GUARD_TEMPLATE = r'''    ; SPORE_DATA_GUARD_ENV_BEGIN
    ${If} $SporePreserveExistingData == 1
    ${AndIf} ${FileExists} "$INSTDIR\.env"
      DetailPrint "Preserving existing Spore configuration: $INSTDIR\.env"
    ${Else}
{env_line}
    ${EndIf}
    ; SPORE_DATA_GUARD_ENV_END'''

SKILLS_FILE_GUARD_TEMPLATE = r'''    ; SPORE_DATA_GUARD_SKILLS_BEGIN
    ${If} $SporePreserveExistingData == 1
    ${AndIf} ${FileExists} "$INSTDIR\skills\*"
      DetailPrint "Preserving existing Spore skills directory: $INSTDIR\skills"
    ${Else}
{skills_lines}
    ${EndIf}
    ; SPORE_DATA_GUARD_SKILLS_END'''


def read_nsis(path: Path) -> tuple[str, str]:
    raw = path.read_bytes()
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16"), "utf-16"
    try:
        return raw.decode("utf-8-sig"), "utf-8-sig"
    except UnicodeDecodeError:
        return raw.decode("utf-8"), "utf-8"


def write_nsis(path: Path, text: str, encoding: str) -> None:
    path.write_text(text, encoding=encoding, newline="")


def patch_installer_text(text: str) -> tuple[str, bool]:
    """Return the patched NSIS source and whether it changed."""
    if PATCH_MARKER in text:
        return text, False

    newline = "\r\n" if "\r\n" in text else "\n"
    normalized = text.replace("\r\n", "\n")

    reinstall_var_anchor = "Var ReinstallPageCheck\n"
    if normalized.count(reinstall_var_anchor) != 1:
        raise RuntimeError("Unable to find Tauri reinstall-page anchor in installer.nsi")
    normalized = normalized.replace(
        reinstall_var_anchor,
        DATA_GUARD_BLOCK + "\n\n" + reinstall_var_anchor,
        1,
    )

    reinstall_function_anchor = "Function PageReinstall\n"
    if normalized.count(reinstall_function_anchor) != 1:
        raise RuntimeError("Unable to find Tauri PageReinstall function in installer.nsi")
    normalized = normalized.replace(
        reinstall_function_anchor,
        reinstall_function_anchor + REINSTALL_SKIP_BLOCK + "\n",
        1,
    )

    env_lines = [
        line
        for line in normalized.splitlines()
        if 'File /a "/oname=.env"' in line
    ]
    if len(env_lines) != 1:
        raise RuntimeError(
            f"Expected exactly one bundled .env File instruction, found {len(env_lines)}"
        )
    env_line = env_lines[0]
    normalized = normalized.replace(
        env_line,
        ENV_FILE_GUARD_TEMPLATE.replace("{env_line}", env_line),
        1,
    )

    lines = normalized.splitlines()
    skill_indices = [
        index
        for index, line in enumerate(lines)
        if 'File /a "/oname=skills\\' in line
    ]
    if not skill_indices:
        raise RuntimeError("No bundled skills File instructions found in installer.nsi")
    first_skill, last_skill = skill_indices[0], skill_indices[-1]
    expected_skill_indices = list(range(first_skill, last_skill + 1))
    if skill_indices != expected_skill_indices:
        raise RuntimeError("Bundled skills File instructions are not contiguous")

    skills_lines = "\n".join(lines[first_skill : last_skill + 1])
    guarded_skills = SKILLS_FILE_GUARD_TEMPLATE.replace("{skills_lines}", skills_lines)
    lines[first_skill : last_skill + 1] = guarded_skills.splitlines()
    normalized = "\n".join(lines)
    if text.endswith(("\n", "\r\n")):
        normalized += "\n"

    return normalized.replace("\n", newline), True


def find_makensis(explicit: Path | None) -> Path:
    candidates: list[Path] = []
    if explicit:
        candidates.append(explicit)

    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        root = Path(local_app_data) / "tauri" / "NSIS"
        candidates.extend([root / "Bin" / "makensis.exe", root / "makensis.exe"])

    on_path = shutil.which("makensis") or shutil.which("makensis.exe")
    if on_path:
        candidates.append(Path(on_path))

    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise FileNotFoundError(
        "makensis.exe was not found. Build once with Tauri or pass --makensis explicitly."
    )


def find_bundle_artifact(bundle_dir: Path) -> Path:
    artifacts = sorted(
        (p for p in bundle_dir.glob("*.exe") if p.name.lower() != "nsis-output.exe"),
        key=lambda p: p.stat().st_mtime_ns,
        reverse=True,
    )
    if len(artifacts) != 1:
        names = ", ".join(p.name for p in artifacts) or "none"
        raise RuntimeError(
            f"Expected exactly one Tauri NSIS bundle artifact in {bundle_dir}; found: {names}. "
            "Clean the bundle directory before building."
        )
    return artifacts[0]


def compile_installer(nsi_path: Path, bundle_dir: Path, makensis: Path | None) -> Path:
    compiler = find_makensis(makensis)
    artifact = find_bundle_artifact(bundle_dir)
    compiler_output = nsi_path.parent / "nsis-output.exe"
    if compiler_output.exists():
        compiler_output.unlink()

    print(f"[INFO] Recompiling patched installer with: {compiler}")
    subprocess.run(
        [str(compiler), str(nsi_path.name)],
        cwd=nsi_path.parent,
        check=True,
    )
    if not compiler_output.is_file():
        raise RuntimeError(f"NSIS did not produce expected output: {compiler_output}")

    os.replace(compiler_output, artifact)
    print(f"[OK] Replaced Tauri bundle artifact: {artifact}")
    return artifact


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nsi", type=Path, required=True, help="Generated installer.nsi path")
    parser.add_argument("--compile", action="store_true", help="Recompile after patching")
    parser.add_argument("--bundle-dir", type=Path, help="Tauri target/release/bundle/nsis directory")
    parser.add_argument("--makensis", type=Path, help="Optional explicit makensis.exe path")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    nsi_path = args.nsi.resolve()
    if not nsi_path.is_file():
        raise FileNotFoundError(f"Generated NSIS script not found: {nsi_path}")

    text, encoding = read_nsis(nsi_path)
    patched, changed = patch_installer_text(text)
    if changed:
        write_nsis(nsi_path, patched, encoding)
        print(f"[OK] Added Spore existing-data guard to: {nsi_path}")
    else:
        print(f"[OK] Spore existing-data guard already present: {nsi_path}")

    if args.compile:
        if args.bundle_dir is None:
            raise ValueError("--bundle-dir is required with --compile")
        compile_installer(
            nsi_path=nsi_path,
            bundle_dir=args.bundle_dir.resolve(),
            makensis=args.makensis.resolve() if args.makensis else None,
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1)
