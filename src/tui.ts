import { emitKeypressEvents } from 'node:readline';
import type { Key } from 'node:readline';
import { ProtectedChat } from './chat.js';
import { fail, SealgateError } from './errors.js';

interface Message { role: string; text: string }

// Remote text must never be interpreted as terminal escape commands. Replace
// ciphertext only for display; the original markers still go to Claude intact.
export function displayText(text: string): string {
  return text.replace(/\[\[SEALGATE:v1:[A-Za-z0-9_-]+\]\]/g, '[encrypted]')
    .replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, '')
    .replace(/\t/g, '  ');
}

const segmenter = new Intl.Segmenter(undefined, { granularity: 'grapheme' });
function width(text: string): number {
  if (/\p{Extended_Pictographic}|\p{Regional_Indicator}|[\u1100-\u115f\u2329\u232a\u2e80-\ua4cf\uac00-\ud7a3\uf900-\ufaff\ufe10-\ufe6f\uff01-\uff60\uffe0-\uffe6]/u.test(text)) return 2;
  return /^\p{Mark}+$/u.test(text) ? 0 : 1;
}

export function wrapText(text: string, columns: number): string[] {
  const lines: string[] = [];
  for (const line of displayText(text).split('\n')) {
    let current = '';
    let used = 0;
    for (const { segment } of segmenter.segment(line)) {
      const cells = width(segment);
      if (used + cells > columns && current) { lines.push(current); current = ''; used = 0; }
      current += segment;
      used += cells;
    }
    lines.push(current);
  }
  return lines;
}

export async function runTui(chat: ProtectedChat): Promise<void> {
  const input = process.stdin;
  const output = process.stdout;
  if (!input.isTTY || !output.isTTY) fail('sealgate chat requires an interactive terminal. Use sealgate protect for piped input.');
  const messages: Message[] = [{ role: 'sealgate', text: 'Write a prompt below. Ctrl-S protects it and sends it to Claude. Enter adds a line.\n/new starts a fresh conversation; /quit exits. Submit commands with Ctrl-S.\nThe trusted detector sees your input and can miss secrets. Tool approvals are not interactive.' }];
  let draft = '';
  let cursor = 0;
  let status = 'Ready';
  let busy = false;
  let exiting = false;
  let pasting = false;
  let scroll = 0;
  let controller: AbortController | undefined;
  let renderTimer: ReturnType<typeof setTimeout> | undefined;
  let started = 0;
  const wasRaw = input.isRaw;

  await new Promise<void>(resolve => {
    const draw = (): void => {
      renderTimer = undefined;
      if (exiting) return;
      const columns = Math.max(4, (output.columns || 80) - 1);
      const rows = Math.max(4, output.rows || 24);
      const composer = wrapText(draft || 'Type your prompt…', columns);
      const cursorLines = wrapText(draft.slice(0, cursor), columns);
      const composerHeight = Math.min(6, Math.max(1, composer.length), Math.max(1, rows - 5));
      const composerStart = Math.max(0, cursorLines.length - composerHeight);
      const historyHeight = Math.max(0, rows - composerHeight - 4);
      const history = messages.flatMap(message => wrapText(`${message.role}\n${message.text}\n`, columns));
      scroll = Math.min(scroll, Math.max(0, history.length - historyHeight));
      const end = Math.max(0, history.length - scroll);
      const visible = history.slice(Math.max(0, end - historyHeight), end);
      while (visible.length < historyHeight) visible.unshift('');
      const elapsed = busy ? ` (${Math.floor((Date.now() - started) / 1000)}s)` : '';
      const screen = [
        wrapText('SEALGATE · protected chat with Claude Code', columns)[0],
        ...visible,
        wrapText(`${status}${elapsed}${scroll ? ' · scrolled' : ''}`, columns)[0],
        '─'.repeat(columns),
        ...composer.slice(composerStart, composerStart + composerHeight),
        wrapText('Ctrl-S send · Enter newline · Ctrl-U clear · Ctrl-C cancel/exit · PgUp/PgDn', columns)[0],
      ];
      const cursorRow = 4 + historyHeight + cursorLines.length - 1 - composerStart;
      const lastLine = cursorLines.at(-1) ?? '';
      const cursorColumn = Math.min(columns, [...segmenter.segment(lastLine)].reduce((sum, item) => sum + width(item.segment), 0) + 1);
      output.write('\x1b[?25l\x1b[H' + screen.map(line => line + '\x1b[K').join('\r\n') + '\x1b[J' +
        `\x1b[${Math.min(rows, cursorRow)};${cursorColumn}H` + (busy ? '' : '\x1b[?25h'));
    };
    const schedule = (): void => {
      if (!renderTimer && !exiting) renderTimer = setTimeout(draw, 35);
    };
    const cleanup = (): void => {
      clearTimeout(renderTimer);
      clearInterval(ticker);
      input.off('keypress', keypress);
      input.off('end', exit);
      input.off('error', exit);
      output.off('resize', schedule);
      output.off('error', exit);
      process.off('SIGTERM', exit);
      process.off('SIGINT', exit);
      try { input.setRawMode(wasRaw); } catch { /* The terminal may have disconnected. */ }
      input.pause();
      output.write('\x1b[?2004l\x1b[?25h\x1b[?1049l');
      draft = '';
      messages.length = 0;
      resolve();
    };
    const exit = (): void => {
      if (exiting) return;
      exiting = true;
      controller?.abort();
      if (!busy) cleanup();
    };
    const submit = async (): Promise<void> => {
      if (busy || !draft.trim()) return;
      const command = draft.trim();
      if (command === '/quit') { exit(); return; }
      if (command === '/new') {
        chat.reset(); messages.length = 0; draft = ''; cursor = 0; scroll = 0;
        status = 'New conversation'; schedule(); return;
      }
      busy = true;
      started = Date.now();
      scroll = 0;
      controller = new AbortController();
      let assistant: Message | undefined;
      try {
        const result = await chat.send(draft, {
          onProtected: protectedPrompt => {
            // Keep only a readable protected view in UI history, never the original.
            messages.push({ role: 'You · protected', text: displayText(protectedPrompt) });
            assistant = { role: 'Claude', text: '' };
            messages.push(assistant);
            draft = ''; cursor = 0;
            if (messages.length > 40) messages.splice(0, messages.length - 40);
            schedule();
          },
          onText: text => { if (assistant) assistant.text += text; schedule(); },
          onActivity: text => { status = text; schedule(); },
        }, controller.signal);
        if (assistant) assistant.text = result.text;
        status = result.permissionDenials ? 'Done · a tool needed approval and was denied' : 'Ready';
      } catch (error) {
        const message = error instanceof SealgateError ? error.message : 'Chat request failed.';
        messages.push({ role: 'sealgate', text: message + (assistant ? '\nConversation reset after the incomplete Claude turn.' : '') });
        status = 'Nothing further sent · edit or retry';
      } finally {
        busy = false;
        controller = undefined;
        if (exiting) cleanup();
        else schedule();
      }
    };
    const insert = (text: string): void => {
      if (draft.length + text.length > 1024 * 1024) { status = 'Prompt is too large'; return; }
      draft = draft.slice(0, cursor) + text + draft.slice(cursor);
      cursor += text.length;
    };
    const keypress = (text: string | undefined, key: Key): void => {
      if (key.name === 'paste-start') { pasting = true; return; }
      if (key.name === 'paste-end') { pasting = false; return; }
      if (!pasting && key.ctrl && key.name === 'd') { exit(); return; }
      if (!pasting && key.ctrl && key.name === 'c') {
        if (busy) { status = 'Canceling…'; controller?.abort(); schedule(); }
        else exit();
        return;
      }
      if (key.name === 'pageup') { scroll += 10; schedule(); return; }
      if (key.name === 'pagedown') { scroll = Math.max(0, scroll - 10); schedule(); return; }
      if (busy || exiting) return;
      if (pasting) insert(key.name === 'return' ? '\n' : text ?? '');
      else if (key.ctrl && key.name === 's') { void submit(); return; }
      else if (key.ctrl && key.name === 'u') { draft = ''; cursor = 0; }
      else if (key.name === 'return' || (key.ctrl && key.name === 'j')) insert('\n');
      else if (key.name === 'backspace') {
        const previous = [...segmenter.segment(draft.slice(0, cursor))].at(-1);
        if (previous) { draft = draft.slice(0, previous.index) + draft.slice(cursor); cursor = previous.index; }
      } else if (key.name === 'left') cursor = [...segmenter.segment(draft.slice(0, cursor))].at(-1)?.index ?? 0;
      else if (key.name === 'right') cursor += [...segmenter.segment(draft.slice(cursor))][0]?.segment.length ?? 0;
      else if (key.name === 'home' || (key.ctrl && key.name === 'a')) cursor = 0;
      else if (key.name === 'end' || (key.ctrl && key.name === 'e')) cursor = draft.length;
      else if (!key.ctrl && !key.meta && text && !text.includes('\x1b')) insert(text);
      schedule();
    };
    const ticker = setInterval(() => { if (busy) schedule(); }, 1000);
    emitKeypressEvents(input);
    input.setRawMode(true);
    input.resume();
    input.on('keypress', keypress);
    input.on('end', exit);
    input.on('error', exit);
    output.on('resize', schedule);
    output.on('error', exit);
    process.on('SIGTERM', exit);
    process.on('SIGINT', exit);
    output.write('\x1b[?1049h\x1b[?2004h\x1b[2J');
    draw();
  });
}
