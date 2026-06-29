function initComposeHighlighting(textareaId) {
  const textarea = document.getElementById(textareaId);
  if (!textarea || !window.Prism) return;
  if (textarea.dataset.highlightInit) return;
  textarea.dataset.highlightInit = 'true';

  const container = document.createElement('div');
  container.className = 'syntax-highlight-container';
  textarea.parentNode.insertBefore(container, textarea);
  container.appendChild(textarea);

  const pre = document.createElement('pre');
  pre.className = 'syntax-highlight-pre visible';
  const code = document.createElement('code');
  code.className = 'language-yaml';
  pre.appendChild(code);
  container.appendChild(pre);

  function updateHighlight() {
    code.textContent = textarea.value;
    Prism.highlightElement(code);
  }

  updateHighlight();
  textarea.classList.add('hidden');

  textarea.addEventListener('blur', () => {
    updateHighlight();
    textarea.classList.add('hidden');
    pre.classList.add('visible');
    const editBtn = document.getElementById(textareaId + '-edit');
    const checkBtn = document.getElementById(textareaId + '-check');
    if (editBtn) editBtn.style.display = '';
    if (checkBtn) checkBtn.style.display = 'none';
    updateSaveVisibility(textareaId);
  });

  textarea.addEventListener('input', () => {
    updateSaveVisibility(textareaId);
  });
}

function enableComposeEdit(editorId) {
  const textarea = document.getElementById(editorId);
  if (!textarea) return;
  const container = textarea.closest('.syntax-highlight-container');
  if (!container) return;
  const pre = container.querySelector('.syntax-highlight-pre');
  if (pre) pre.classList.remove('visible');
  textarea.classList.remove('hidden');
  textarea.focus();
  const editBtn = document.getElementById(editorId + '-edit');
  const checkBtn = document.getElementById(editorId + '-check');
  if (editBtn) editBtn.style.display = 'none';
  if (checkBtn) checkBtn.style.display = '';
}

function updateSaveVisibility(editorId) {
  const textarea = document.getElementById(editorId);
  if (!textarea) return;
  const saveId = textarea.dataset.saveId;
  const saveBtn = document.getElementById(saveId);
  if (!saveBtn) return;
  const original = window._composeEditorState?.originalValue || '';
  const hasChanges = textarea.value !== original;
  saveBtn.style.display = hasChanges ? '' : 'none';
}

function checkComposeSyntax(editorId) {
  const textarea = document.getElementById(editorId);
  if (!textarea) return;
  const statusId = textarea.dataset.statusId;
  const statusEl = document.getElementById(statusId);
  if (!statusEl) return;

  const content = textarea.value;
  try {
    const lines = content.split('\n');
    let indent = 0;
    let hasError = false;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.trim() === '' || line.trim().startsWith('#')) continue;
      const spaces = line.match(/^(\s*)/)[1].length;
      if (spaces % 2 !== 0) {
        statusEl.textContent = `Line ${i + 1}: Odd indentation (use 2 spaces)`;
        statusEl.style.color = 'var(--yellow)';
        hasError = true;
        break;
      }
      if (line.includes('\t')) {
        statusEl.textContent = `Line ${i + 1}: Tab character found (use spaces)`;
        statusEl.style.color = 'var(--yellow)';
        hasError = true;
        break;
      }
    }
    if (!hasError) {
      statusEl.textContent = 'Syntax OK';
      statusEl.style.color = 'var(--green)';
    }
  } catch (e) {
    statusEl.textContent = 'Check failed: ' + e.message;
    statusEl.style.color = 'var(--red)';
  }
}

// ─── Dockerfile editor (container detail modal) ───────────────────────────────
// Mirrors the compose editor's blur-to-highlight behavior but is self-contained
// (its own state) so it can coexist with the compose editor in the same modal.
let _dockerfileEditorState = { editorId: '', originalValue: '' };

function initDockerfileHighlighting(textareaId) {
  const textarea = document.getElementById(textareaId);
  if (!textarea || !window.Prism) return;
  if (textarea.dataset.highlightInit) return;
  textarea.dataset.highlightInit = 'true';

  const container = textarea.closest('.dockerfile-edit-container');
  if (!container) return;

  const pre = document.createElement('pre');
  pre.className = 'dockerfile-view visible';
  const code = document.createElement('code');
  code.className = 'language-docker';
  pre.appendChild(code);
  container.insertBefore(pre, textarea);

  function updateHighlight() {
    code.textContent = textarea.value;
    Prism.highlightElement(code);
  }

  updateHighlight();
  textarea.classList.add('hidden');

  textarea.addEventListener('blur', () => {
    updateHighlight();
    textarea.classList.add('hidden');
    pre.classList.add('visible');
    const editBtn = document.getElementById(textareaId + '-edit');
    if (editBtn) editBtn.style.display = '';
    updateDockerfileSaveVisibility(textareaId);
  });

  textarea.addEventListener('input', () => {
    updateDockerfileSaveVisibility(textareaId);
  });
}

function enableDockerfileEdit(editorId) {
  const textarea = document.getElementById(editorId);
  if (!textarea) return;
  const container = textarea.closest('.dockerfile-edit-container');
  if (!container) return;
  const pre = container.querySelector('.dockerfile-view');
  if (pre) pre.classList.remove('visible');
  textarea.classList.remove('hidden');
  textarea.focus();
  const editBtn = document.getElementById(editorId + '-edit');
  if (editBtn) editBtn.style.display = 'none';
}

function updateDockerfileSaveVisibility(editorId) {
  const textarea = document.getElementById(editorId);
  if (!textarea) return;
  const saveId = textarea.dataset.saveId;
  const saveBtn = document.getElementById(saveId);
  if (!saveBtn) return;
  const original = window._dockerfileEditorState?.originalValue || '';
  saveBtn.style.display = textarea.value !== original ? '' : 'none';
}
