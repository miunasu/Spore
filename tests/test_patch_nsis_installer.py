from pathlib import Path

from scripts.patch_nsis_installer import patch_installer_text, read_nsis, write_nsis


MINIMAL_TAURI_INSTALLER = r'''Unicode true
Var ReinstallPageCheck
Function PageReinstall
  DetailPrint "reinstall"
FunctionEnd
Section Install
    File /a "/oname=.env" "C:\source\.env"
    File /a "/oname=skills\first\SKILL.md" "C:\source\skills\first\SKILL.md"
    File /a "/oname=skills\second\SKILL.md" "C:\source\skills\second\SKILL.md"
SectionEnd
'''


def test_patch_adds_data_guard_and_is_idempotent() -> None:
    patched, changed = patch_installer_text(MINIMAL_TAURI_INSTALLER)

    assert changed is True
    assert "; SPORE_DATA_GUARD_BEGIN" in patched
    assert "Page custom SporeExistingDataPage SporeExistingDataPageLeave" in patched
    assert r'IfFileExists "$SporeExistingInstallDir\.spore\*"' in patched
    assert "StrCpy $INSTDIR $SporeExistingInstallDir" in patched
    assert "; SPORE_DATA_GUARD_REINSTALL_SKIP" in patched
    assert "Preserving existing Spore configuration" in patched
    assert r'IfFileExists "$SporeExistingInstallDir\skills\*"' in patched
    assert "; SPORE_DATA_GUARD_SKILLS_BEGIN" in patched
    assert "Preserving existing Spore skills directory" in patched
    assert patched.count('File /a "/oname=.env"') == 1
    assert patched.count('File /a "/oname=skills\\') == 2

    second_pass, changed_again = patch_installer_text(patched)
    assert changed_again is False
    assert second_pass == patched


def test_utf16_generated_installer_round_trip(tmp_path: Path) -> None:
    nsi_path = tmp_path / "installer.nsi"
    write_nsis(nsi_path, MINIMAL_TAURI_INSTALLER, "utf-16")

    loaded, encoding = read_nsis(nsi_path)
    assert encoding == "utf-16"
    patched, changed = patch_installer_text(loaded)
    assert changed is True

    write_nsis(nsi_path, patched, encoding)
    reloaded, reloaded_encoding = read_nsis(nsi_path)
    assert reloaded_encoding == "utf-16"
    assert "; SPORE_DATA_GUARD_BEGIN" in reloaded
