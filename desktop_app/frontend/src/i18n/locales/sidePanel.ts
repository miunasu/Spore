const sidePanel = {
  zh: {
    tabs: {
      note: '笔记',
      output: '输出',
      agents: '智能体',
      prompt: '提示词',
      skills: '技能',
      characters: '角色',
      history: '历史',
    },
    syntax: {
      largeContent: '文件内容较大，仅显示前 {count} 个字符',
      tooManyLines: '仅显示前 {count} 行',
      controlCharsReplaced: '已替换不可见控制字符',
      highlightDisabled: '已关闭语法高亮以避免界面卡死',
      highlightFailed: '语法高亮失败，已切换为纯文本预览',
      separator: '；',
    },
  },
  en: {
    tabs: {
      note: 'Note',
      output: 'Output',
      agents: 'Agents',
      prompt: 'Prompt',
      skills: 'Skills',
      characters: 'Characters',
      history: 'History',
    },
    syntax: {
      largeContent: 'File is large; showing only the first {count} characters',
      tooManyLines: 'Showing only the first {count} lines',
      controlCharsReplaced: 'Invisible control characters replaced',
      highlightDisabled: 'Syntax highlighting disabled to keep the UI responsive',
      highlightFailed: 'Syntax highlighting failed; showing plain text instead',
      separator: '; ',
    },
  },
};

export default sidePanel;
