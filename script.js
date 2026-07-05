const CHECK_LABELS = {
  length_ok: "12+ characters",
  has_lower: "Lowercase letter",
  has_upper: "Uppercase letter",
  has_digit: "Number",
  has_symbol: "Special character",
  not_common: "Not a common password",
  no_sequential: "No sequential pattern",
  no_repeats: "No repeated characters",
  not_personal_info: "No personal info",
};

const SCORE_COLORS = ["#FF5C6C", "#FF5C6C", "#FFC24B", "#2FE6C6", "#2FE6C6"];

const passwordEl = document.getElementById("password");
const usernameEl = document.getElementById("username");
const toggleBtn = document.getElementById("toggle");
const meterEl = document.getElementById("meter");
const meterLabel = document.getElementById("meterLabel");
const statsEl = document.getElementById("stats");
const entropyEl = document.getElementById("entropy");
const lengthEl = document.getElementById("length");
const checklistEl = document.getElementById("checklist");
const suggestionsEl = document.getElementById("suggestions");
const saveBtn = document.getElementById("saveBtn");
const suggestBtn = document.getElementById("suggestBtn");
const noteEl = document.getElementById("note");

let lastScore = -1;
let debounceTimer = null;

toggleBtn.addEventListener("click", () => {
  passwordEl.type = passwordEl.type === "password" ? "text" : "password";
});

passwordEl.addEventListener("input", () => {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(runAnalysis, 200);
});
usernameEl.addEventListener("input", () => {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(runAnalysis, 200);
});

async function runAnalysis() {
  const password = passwordEl.value;
  const username = usernameEl.value;

  if (!password) {
    resetUI();
    return;
  }

  const res = await fetch("/api/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password, username }),
  });
  const data = await res.json();
  renderResult(data);
}

function resetUI() {
  statsEl.hidden = true;
  meterLabel.textContent = "Awaiting input";
  checklistEl.innerHTML = "";
  suggestionsEl.classList.remove("show");
  saveBtn.disabled = true;
  [...meterEl.children].forEach((seg) => (seg.style.background = ""));
}

function renderResult(data) {
  lastScore = data.score;
  statsEl.hidden = false;
  entropyEl.textContent = data.entropy_bits;
  lengthEl.textContent = data.length;
  meterLabel.textContent = data.label;

  [...meterEl.children].forEach((seg, i) => {
    seg.style.background = i <= data.score ? SCORE_COLORS[data.score] : "";
  });

  checklistEl.innerHTML = Object.entries(data.checks)
    .map(([key, passed]) => {
      const label = CHECK_LABELS[key] || key;
      return `<li class="${passed ? "pass" : "fail"}">${label}</li>`;
    })
    .join("");

  if (data.suggestions && data.suggestions.length) {
    suggestionsEl.innerHTML = `<strong>Suggestions</strong><ul>${data.suggestions
      .map((s) => `<li>${s}</li>`)
      .join("")}</ul>`;
    suggestionsEl.classList.add("show");
  } else {
    suggestionsEl.classList.remove("show");
  }

  saveBtn.disabled = !(usernameEl.value && data.score >= 3 && !data.reused);
}

suggestBtn.addEventListener("click", async () => {
  const res = await fetch("/api/suggest?length=16");
  const data = await res.json();
  passwordEl.type = "text";
  passwordEl.value = data.password;
  runAnalysis();
  noteEl.textContent = "Generated a fresh 16-character password — copy it now.";
});

saveBtn.addEventListener("click", async () => {
  const password = passwordEl.value;
  const username = usernameEl.value;
  const res = await fetch("/api/save", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password, username }),
  });
  const data = await res.json();
  if (res.ok) {
    noteEl.textContent = "Saved to password history for reuse checks.";
  } else {
    noteEl.textContent = data.error || "Could not save password.";
  }
});
