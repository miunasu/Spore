from typing import Dict, List

from .utils.characters import load_character_document, get_all_characters_summary


class CharacterManager:
    """管理当前选择的角色身份，同时只能存在一个角色。"""

    def __init__(self, capacity: int = 1) -> None:
        self.capacity = 1  # 固定为1，同时只能存在一个角色
        self._characters: List[Dict[str, str]] = []

    def select(self, character_name: str) -> Dict:
        if not character_name or not character_name.strip():
            return {"success": False, "error": "characterName 不能为空"}

        doc = load_character_document(character_name)
        if not doc:
            return {"success": False, "error": f"未找到角色: {character_name}"}

        normalized = doc["name"].lower()
        self._characters = [c for c in self._characters if c["name"].lower() != normalized]
        self._characters.append(
            {"name": doc["name"], "path": doc["path"], "content": doc["content"]}
        )

        removed: List[Dict[str, str]] = []
        while len(self._characters) > self.capacity:
            removed.append(self._characters.pop(0))

        message_parts = [f"已选择角色: {doc['name']}"]
        if removed:
            removed_names = ", ".join(r["name"] for r in removed)
            message_parts.append(f"已替换角色: {removed_names}")

        return {
            "success": True,
            "characters": self.get_characters_summary(),
            "message": "；".join(message_parts),
        }

    def remove(self, character_name: str) -> Dict:
        if not character_name or not character_name.strip():
            return {"success": False, "error": "characterName 不能为空"}

        target = character_name.strip().lower()
        before = len(self._characters)
        self._characters = [c for c in self._characters if c["name"].lower() != target]
        after = len(self._characters)

        if before == after:
            return {"success": False, "error": f"角色不存在: {character_name}"}

        return {
            "success": True,
            "characters": self.get_characters_summary(),
            "message": f"已移除角色: {character_name}",
        }

    def get_characters(self) -> List[Dict[str, str]]:
        return [c.copy() for c in self._characters]

    def get_characters_summary(self) -> List[str]:
        return [c["name"] for c in self._characters]

    def format_for_prompt(self) -> str:
        if not self._characters:
            return "当前未选择职业"

        parts: List[str] = []
        for character in self._characters:
            content = character["content"].strip()
            parts.append(f"\n{content}\n")
        return "\n".join(parts).strip()


_character_manager = CharacterManager()


def select_character(character_name: str) -> Dict:
    return _character_manager.select(character_name)


def remove_character(character_name: str) -> Dict:
    return _character_manager.remove(character_name)


def get_selected_characters() -> List[Dict[str, str]]:
    return _character_manager.get_characters()


def get_current_characters_for_prompt() -> str:
    return _character_manager.format_for_prompt()


# get_all_characters_list 已移除，直接使用 get_all_characters_summary
