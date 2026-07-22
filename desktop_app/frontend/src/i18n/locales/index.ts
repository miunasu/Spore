/**
 * Locale registry. Each namespace lives in its own file exporting
 * `{ zh: {...}, en: {...} }`, so components/areas can be localized
 * independently without merge conflicts.
 *
 * Keys are addressed as `<namespace>.<key>`, e.g. `common.confirm`.
 */
import type { Lang } from '../index';

import common from './common';
import app from './app';
import titleBar from './titleBar';
import mainLayout from './mainLayout';
import chatPanel from './chatPanel';
import messageList from './messageList';
import messageDetail from './messageDetail';
import todoBar from './todoBar';
import confirmBar from './confirmBar';
import agentActivityBar from './agentActivityBar';
import inputArea from './inputArea';
import commandMenu from './commandMenu';
import securityModal from './securityModal';
import sidePanel from './sidePanel';
import agentMonitor from './agentMonitor';
import fileManager from './fileManager';
import fileEditor from './fileEditor';
import noteEditor from './noteEditor';
import logPanel from './logPanel';
import logArea from './logArea';
import miniModeView from './miniModeView';
import modeSelector from './modeSelector';
import stores from './stores';

type NamespacePack = { zh: Record<string, unknown>; en: Record<string, unknown> };

const namespaces: Record<string, NamespacePack> = {
  common,
  app,
  titleBar,
  mainLayout,
  chatPanel,
  messageList,
  messageDetail,
  todoBar,
  confirmBar,
  agentActivityBar,
  inputArea,
  commandMenu,
  securityModal,
  sidePanel,
  agentMonitor,
  fileManager,
  fileEditor,
  noteEditor,
  logPanel,
  logArea,
  miniModeView,
  modeSelector,
  stores,
};

const buildForLang = (lang: Lang): Record<string, unknown> => {
  const out: Record<string, unknown> = {};
  for (const [ns, pack] of Object.entries(namespaces)) {
    out[ns] = pack[lang];
  }
  return out;
};

export const messages: Record<Lang, Record<string, unknown>> = {
  zh: buildForLang('zh'),
  en: buildForLang('en'),
};
