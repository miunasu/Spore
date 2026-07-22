const messageDetail = {
  zh: {
    hideDetail: '隐藏详情',
    viewDetail: '查看详情',
    sentMessages: '本次发送给LLM的消息 ({count}条)',
    sentMessagesNote: '仅显示本次请求的内容（system + 当前用户输入），不包含历史记忆',
    rawResponse: 'LLM返回的原始响应（包含协议标记）',
  },
  en: {
    hideDetail: 'Hide details',
    viewDetail: 'View details',
    sentMessages: 'Messages sent to the LLM ({count})',
    sentMessagesNote: 'Shows only this request (system + current user input), excluding history memory',
    rawResponse: 'Raw LLM response (with protocol markers)',
  },
};

export default messageDetail;
