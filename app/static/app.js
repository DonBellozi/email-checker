const $ = (sel) => document.querySelector(sel);

for (const tab of document.querySelectorAll('.tab')) {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(x => x.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(tab.dataset.tab).classList.add('active');
  });
}

function escapeHtml(text) {
  return String(text ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
}

function renderHighlighted(text, highlights) {
  if (!highlights || highlights.length === 0) return escapeHtml(text);
  const sorted = [...highlights].sort((a,b) => a.start - b.start || a.end - b.end);
  let out = '', pos = 0;
  for (const h of sorted) {
    const start = Math.max(pos, h.start);
    const end = Math.max(start, h.end);
    if (start > pos) out += escapeHtml(text.slice(pos, start));
    const cls = h.kind === 'domain' ? 'mark-domain' : 'mark-syntax';
    out += `<span class="${cls}">${escapeHtml(text.slice(start, end))}</span>`;
    pos = Math.max(pos, end);
  }
  out += escapeHtml(text.slice(pos));
  return out;
}

async function postJson(url, text) {
  const response = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({text})
  });
  if (!response.ok) {
    let detail = 'Ошибка запроса';
    try { detail = (await response.json()).detail || detail; } catch (_) {}
    throw new Error(detail);
  }
  return response.json();
}

$('#checkBtn').addEventListener('click', async () => {
  const btn = $('#checkBtn');
  btn.disabled = true;
  btn.textContent = 'Проверяем…';
  try {
    const data = await postJson('/api/check', $('#emailInput').value);
    const summary = $('#emailSummary');
    summary.classList.remove('hidden');
    const overflow = data.overflow ? '<strong>Лимит достигнут:</strong> обработаны первые 100 адресов.' : '';
    summary.innerHTML = `<span>Найдено: <strong>${data.count}</strong></span><span>Уникальных: <strong>${data.unique_count}</strong></span><span>Дубли: <strong>${data.duplicate_count}</strong></span>${overflow}`;

    const tbody = $('#emailResults');
    tbody.innerHTML = '';
    for (const [idx, row] of data.results.entries()) {
      const tr = document.createElement('tr');
      const suggestion = row.suggestion ? `<span class="suggestion">Возможно: ${escapeHtml(row.suggestion)}</span>` : '';
      tr.innerHTML = `
        <td>${idx + 1}</td>
        <td class="source-cell">${escapeHtml(row.source)}</td>
        <td class="status-col status-${escapeHtml(row.status)}">${escapeHtml(row.symbol)}</td>
        <td class="email-cell">${renderHighlighted(row.cleaned, row.highlights)}${suggestion}</td>
        <td><span class="result-main">${escapeHtml(row.result)}</span></td>`;
      tbody.appendChild(tr);
    }
    $('#emailTableWrap').classList.toggle('hidden', data.results.length === 0);
    if (data.results.length === 0) summary.innerHTML += '<span>Адреса в тексте не найдены.</span>';
  } catch (e) {
    $('#emailSummary').classList.remove('hidden');
    $('#emailSummary').textContent = e.message;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Проверить';
  }
});

$('#deliveryBtn').addEventListener('click', async () => {
  const btn = $('#deliveryBtn');
  btn.disabled = true;
  btn.textContent = 'Разбираем…';
  try {
    const data = await postJson('/api/delivery', $('#deliveryInput').value);
    const box = $('#deliveryResults');
    box.innerHTML = '';
    if (data.message) box.innerHTML = `<div class="alert">${escapeHtml(data.message)}</div>`;
    for (const item of data.items) {
      const div = document.createElement('div');
      div.className = 'delivery-card';
      div.innerHTML = `
        <h3 class="status-${escapeHtml(item.status)}">${escapeHtml(item.symbol)} ${escapeHtml(item.title)}</h3>
        <div>${escapeHtml(item.explanation)}</div>
        <div class="delivery-meta">
          ${item.recipient ? `<div class="muted">Получатель</div><div class="email-cell">${renderHighlighted(item.recipient, item.recipient_highlights)}</div>` : ''}
          ${item.recipient_check ? `<div class="muted">Проверка адреса</div><div><span class="result-main status-error">${escapeHtml(item.recipient_check)}</span>${item.recipient_check_note ? `<span class="result-note">${escapeHtml(item.recipient_check_note)}</span>` : ''}</div>` : ''}
          ${item.action ? `<div class="muted">Action</div><div>${escapeHtml(item.action)}</div>` : ''}
          ${item.smtp_code ? `<div class="muted">SMTP-код</div><div>${escapeHtml(item.smtp_code)}</div>` : ''}
          ${item.enhanced_code ? `<div class="muted">Статус</div><div>${escapeHtml(item.enhanced_code)}</div>` : ''}
          ${item.message_size ? `<div class="muted">Размер письма</div><div>${escapeHtml(item.message_size)}</div>` : ''}
          ${item.size_limit ? `<div class="muted">Допустимый размер</div><div>${escapeHtml(item.size_limit)}</div>` : ''}
          ${item.size_excess ? `<div class="muted">Превышение</div><div>${escapeHtml(item.size_excess)}</div>` : ''}
        </div>`;
      box.appendChild(div);
    }
  } catch (e) {
    $('#deliveryResults').innerHTML = `<div class="alert error">${escapeHtml(e.message)}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Расшифровать';
  }
});
