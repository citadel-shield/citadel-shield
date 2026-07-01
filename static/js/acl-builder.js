let groups = [{ name: "group:home", members: "alice@, bob@" }];
let rules = [{ src: "group:home", dst: "group:home" }];

function escapeHtml(str) {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function renderGroups() {
  const el = document.getElementById("groups-list");
  el.innerHTML = groups.map((g, i) => `
    <div class="group-row">
      <input type="text" value="${escapeHtml(g.name)}" data-idx="${i}" data-field="name" class="group-name-input" placeholder="group:home">
      <input type="text" value="${escapeHtml(g.members)}" data-idx="${i}" data-field="members" class="group-members-input" placeholder="alice@, bob@">
      <button type="button" class="btn-remove" data-idx="${i}" data-action="remove-group">&times;</button>
    </div>
  `).join("");
}

function renderRules() {
  const el = document.getElementById("rules-list");
  const groupNames = groups.map(g => g.name).filter(Boolean);
  el.innerHTML = rules.map((r, i) => `
    <div class="rule-row">
      <select data-idx="${i}" data-field="src" class="rule-select">
        ${groupNames.map(n => `<option value="${escapeHtml(n)}"${r.src === n ? " selected" : ""}>${escapeHtml(n)}</option>`).join("")}
      </select>
      <span class="rule-arrow">&rarr;</span>
      <select data-idx="${i}" data-field="dst" class="rule-select">
        ${groupNames.map(n => `<option value="${escapeHtml(n)}"${r.dst === n ? " selected" : ""}>${escapeHtml(n)}</option>`).join("")}
      </select>
      <button type="button" class="btn-remove" data-idx="${i}" data-action="remove-rule">&times;</button>
    </div>
  `).join("");
}

function renderJSON() {
  const policy = { groups: {}, acls: [] };
  groups.forEach(g => {
    if (!g.name) return;
    const members = g.members.split(",").map(m => m.trim()).filter(Boolean);
    policy.groups[g.name] = members;
  });
  rules.forEach(r => {
    if (!r.src || !r.dst) return;
    policy.acls.push({ action: "accept", src: [r.src], dst: [r.dst + ":*"] });
  });
  document.getElementById("json-output").textContent = JSON.stringify(policy, null, 2);
}

function renderAll() {
  renderGroups();
  renderRules();
  renderJSON();
}

document.getElementById("add-group").addEventListener("click", () => {
  groups.push({ name: "", members: "" });
  renderAll();
});

document.getElementById("add-rule").addEventListener("click", () => {
  const firstGroup = groups[0] ? groups[0].name : "";
  rules.push({ src: firstGroup, dst: firstGroup });
  renderAll();
});

document.getElementById("groups-list").addEventListener("input", (e) => {
  const idx = e.target.getAttribute("data-idx");
  const field = e.target.getAttribute("data-field");
  if (idx === null || !field) return;
  groups[idx][field] = e.target.value;
  renderJSON();
  renderRules();
});

document.getElementById("groups-list").addEventListener("click", (e) => {
  if (e.target.getAttribute("data-action") === "remove-group") {
    const idx = parseInt(e.target.getAttribute("data-idx"), 10);
    groups.splice(idx, 1);
    renderAll();
  }
});

document.getElementById("rules-list").addEventListener("change", (e) => {
  const idx = e.target.getAttribute("data-idx");
  const field = e.target.getAttribute("data-field");
  if (idx === null || !field) return;
  rules[idx][field] = e.target.value;
  renderJSON();
});

document.getElementById("rules-list").addEventListener("click", (e) => {
  if (e.target.getAttribute("data-action") === "remove-rule") {
    const idx = parseInt(e.target.getAttribute("data-idx"), 10);
    rules.splice(idx, 1);
    renderAll();
  }
});

document.getElementById("copy-json").addEventListener("click", () => {
  const text = document.getElementById("json-output").textContent;
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById("copy-json");
    const original = btn.textContent;
    btn.textContent = "copied";
    setTimeout(() => { btn.textContent = original; }, 1200);
  });
});

renderAll();
